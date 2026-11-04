"""Paired experiments: trusted reference masking, blind prediction, then sealed scoring."""
from __future__ import annotations

from copy import deepcopy
import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from datetime import datetime

from research_core import digest, load, now, save
from .agent import ToolBroker, deterministic_policy, run_agent
from .baselines import coverage, merge, REPLICATION_COMMIT, UNIFIER_COMMIT
from .contracts import TargetContext
from .evidence import EvidenceStore
from .formats import NativeDocument, encoded, package_purl, sha, validate_native, cyclonedx_projection
from .isolated import IsolatedBroker
from .metrics import controlled_mask, evaluate, holm, paired_bootstrap
from .scope import installed_view
from .storage import save
from .targets import metadata_inventory


def build_sources(capture_dir, context):
    root = Path(capture_dir).resolve()
    sources = {}
    all_metadata, actual_target = metadata_inventory(root / "runtime/target")
    if context.target_id != actual_target:
        raise ValueError("TARGET_METADATA_INVENTORY_CHANGED_AFTER_CAPTURE")
    for path in all_metadata:
        # A nested/vendor/test dist-info directory is not a top-level installed distribution.
        if path.parent.parent.name not in {"site-packages", "dist-packages"}:
            continue
        source_id = sha(str(path.relative_to(root)))
        raw = path.read_bytes()
        sources[source_id] = {"kind": "target_metadata", "description": "target:" + str(path.relative_to(root / "runtime/target")),
                              "path": str(path.resolve()), "content_binding": sha({"raw_hex": raw.hex()}),
                              "available_at": load(root / "capture.json")["historical_resolution_horizon"],
                              "availability_kind": "UPPER_BOUND"}
    source_root = root / "source"
    source_eligible = False
    if source_root.is_dir() and (source_root / ".git").is_dir():
        try:
            commit_time = subprocess.check_output(["git", "show", "-s", "--format=%cI", "HEAD"], cwd=source_root, text=True).strip()
            clean = subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=source_root).returncode == 0
            source_eligible = clean and datetime.fromisoformat(commit_time) <= datetime.fromisoformat(context.evidence_cutoff.replace("Z", "+00:00"))
        except (ValueError, subprocess.SubprocessError):
            source_eligible = False
    if source_eligible:
        for path in sorted(source_root.iterdir()):
            if path.name != "pyproject.toml" and not (path.name.startswith("requirements") and path.suffix == ".txt"):
                continue
            if not path.is_file() or path.is_symlink() or path.stat().st_size > 1048576:
                continue
            if subprocess.run(["git", "ls-files", "--error-unmatch", path.name], cwd=source_root,
                              capture_output=True).returncode:
                continue
            raw = path.read_bytes()
            sources[sha("source:" + path.name)] = {"kind": "source_file", "description": "source:" + path.name,
                "path": str(path.resolve()), "content_binding": sha({"raw_hex": raw.hex()}),
                "available_at": load(root / "capture.json")["historical_resolution_horizon"], "availability_kind": "UPPER_BOUND"}
    return sources


def prepare_store(capture_dir, document, store, context, condition):
    root = Path(capture_dir)
    sources = build_sources(root, context)
    # Same raw peers and metadata permissions for all policies. No truth-driven seed selection.
    for name in ("syft.spdx.json", "trivy.spdx.json"):
        p = root / "runtime" / name
        if p.exists():
            peer, _ = installed_view(load(p), context.root_purls)
            store.add(peer, source=name + "#installed-distribution-view", kind="peer_sbom")
    if condition == "fixed":
        for source in sources.values():
            raw = Path(source["path"]).read_bytes()
            if sha({"raw_hex": raw.hex()}) != source["content_binding"]:
                raise ValueError("Evidence file changed during fixed-snapshot capture")
            store.add(raw, source=source["description"], kind=source["kind"],
                      target_id=context.target_id if source["kind"] == "target_metadata" else None,
                      authority="VERIFIED_TARGET" if source["kind"] == "target_metadata" else "SUPPORTED", available_at=source["available_at"],
                      availability_kind=source["availability_kind"])
    return sources


def sbom_peers(capture_dir, observed, context):
    """Give native-SBOM baselines the same scanner observations as the agents.

    In mask experiments a fresh Syft scan can undo simulated damage. This is an
    explicit regeneration control, never hidden evidence of novel inference.
    """
    peers, seen = [("input", observed)], {sha(observed)}
    for name in ("syft", "trivy"):
        path = Path(capture_dir) / "runtime" / (name + ".spdx.json")
        if path.exists():
            view, _ = installed_view(load(path), context.root_purls)
            if sha(view) not in seen:
                peers.append(("regenerated-" + name, view))
                seen.add(sha(view))
    return peers


def score_after_seal(capture_dir, observed, prediction):
    """Evaluation labels are opened after sealing; controlled input generation is separate."""
    root = Path(capture_dir) / "oracle"
    reference = load(root / "installed_reference.cdx.json")
    gold = load(root / "installed_reference.json")
    unresolved = {next((n["purl"] for n in gold["nodes"] if n["name"] == u.get("parent")), None)
                  for u in gold.get("unresolved", [])}
    labels = load(root / "installed_field_labels.json")["fields"]
    return evaluate(reference, observed, prediction, labels, unresolved)


def flat_scores(evaluation):
    return {"new_metadata_f1": (evaluation.get("new_metadata") or {}).get("f1"),
            "new_direct_edge_f1": evaluation["new_edges"]["f1"],
            "whole_metadata_f1": (evaluation.get("whole_metadata") or {}).get("f1"),
            "whole_direct_edge_f1": evaluation["whole_edges"]["f1"],
            "whole_node_f1": (evaluation.get("whole_nodes") or {}).get("f1"),
            "new_node_f1": evaluation["new_nodes"]["f1"]}


def run_case(capture_dir, destination, *, condition="fixed", family="raw", rate=0., mask_seed=11,
             methods=("observed", "single_scanner", "sbom_unifier", "unifier_rules", "deterministic", "single_agent", "multi_agent"),
             budget=64, model=None, gateway=None, repetition=0, isolated=True, max_turns=64, calibration=None,
             single_scanner="syft", mask_origin="scanner"):
    root, out = Path(capture_dir), Path(destination)
    out.mkdir(parents=True, exist_ok=True)
    capture = load(root / "capture.json")
    if capture["status"] != "COMPLETE":
        return {"status": "CAPTURE_FAILED", "project": capture["project"]["name"]}
    context = TargetContext.model_validate(load(root / "context.json"))
    context = context.model_copy(update={"evidence_cutoff": capture["historical_resolution_horizon"],
        "root_purls": context.root_purls or [f"pkg:pypi/{capture['project']['name']}@{capture['project']['version']}"]})
    if mask_origin not in {"scanner", "reference"}:
        raise ValueError("Unknown controlled input origin")
    if family != "raw" and mask_origin == "reference":
        # Only this trusted preparer sees the independent reference. The model,
        # collectors and native-SBOM peers receive no unmasked reference or mask log.
        from controlled_reference import masked_reference
        observed, mask, preparation = masked_reference(root, context.root_purls, family, rate, mask_seed)
        scope_audit = {"profile": "CONTROLLED_INDEPENDENT_INSTALLED_REFERENCE", **preparation}
    else:
        observed, scope_audit = installed_view(load(root / "runtime/syft.spdx.json"), context.root_purls)
        preparation = {"input_origin": "RAW_GENERATOR_DISCREPANCY" if family == "raw" else "SCANNER_OUTPUT_MASK",
                       "raw_input_sha256": digest(root / "runtime/syft.spdx.json"),
                       "oracle_exposed_to_prediction_worker": False}
    if family != "raw" and mask_origin == "scanner":
        observed, mask = controlled_mask(observed, rate, mask_seed, family)
        mask["population"] = "Scanner-observed records; an additional-corruption development experiment, not Track 1"
    # Preserve original case inputs even if a later resume has different parameters.
    def input_artifact(filename, value):
        path = out / filename
        if path.exists():
            if sha(load(path)) != sha(value):
                raise ValueError("CASE_INPUT_CHANGED: " + filename)
        else:
            save(path, value)
    input_artifact("input.spdx.json", observed)
    input_artifact("scope_audit.json", scope_audit)
    input_artifact("input_preparation.json", preparation)
    if family != "raw":
        input_artifact("mask.json", mask)
    sources_at_start = build_sources(root, context)
    evidence_binding = {"sources": {k: {f: v for f, v in source.items() if f != "path"}
                                      for k, source in sources_at_start.items()},
                        "peer_sha256": {p.name: digest(p) for p in (root / "runtime").glob("*.spdx.json")
                                        if p.name in {"syft.spdx.json", "trivy.spdx.json"}}}
    if (out / "evidence_binding.json").exists() and load(out / "evidence_binding.json") != evidence_binding:
        raise ValueError("Evidence inputs changed across a resumed paired case")
    save(out / "evidence_binding.json", evidence_binding)
    records = []
    for method in methods:
        arm = out / method
        arm.mkdir(exist_ok=True)
        spec = {"method": method, "model": model if "agent" in method else None, "condition": condition,
                "budget": budget, "family": family, "rate": rate, "mask_seed": mask_seed, "repetition": repetition,
                "input_sha256": sha(observed), "context_sha256": sha(context.model_dump())}
        spec["input_origin"] = preparation["input_origin"]
        spec["input_preparation_sha256"] = sha(preparation)
        spec["calibration_sha256"] = sha(calibration) if calibration else None
        spec["single_scanner"] = single_scanner
        spec["evidence_input_sha256"] = sha(evidence_binding)
        spec["implementation_sha256"] = sha({p.name: digest(p) for p in Path(__file__).parent.glob("*.py")})
        if (arm / "seal.json").exists():
            seal = load(arm / "seal.json")
            if seal["spec"] != spec or digest(arm / "prediction.spdx.json") != seal["prediction_sha256"]:
                raise ValueError("Resume configuration/prediction mismatch")
            if not (arm / "evaluation.json").exists():
                save(arm / "evaluation.json", score_after_seal(root, observed, load(arm / "prediction.spdx.json")))
            evaluation = load(arm / "evaluation.json")
            prior = load(arm / "record.json") if (arm / "record.json").exists() else {}
            if not prior and (arm / "details.json").exists():
                details = load(arm / "details.json")
                prior = {"status": details.get("status", "COMPLETE"),
                         "llm_api_calls": details.get("llm_api_calls", 0),
                         "duration_seconds": details.get("duration_seconds")}
            record = {**prior, "project": capture["project"]["name"], "method": method,
                            "partition": capture["project"]["partition"], "metrics": flat_scores(evaluation),
                            "case": str(out), **spec}
            records.append(record)
            save(arm / "record.json", record)
            continue
        started = time.monotonic()
        sealed = False
        try:
            if method == "observed":
                prediction, details = deepcopy(observed), {"llm_api_calls": 0}
            elif method == "single_scanner":
                # Syft is a fixed engineering baseline until development selection is frozen.
                prediction, _ = installed_view(load(root / "runtime" / (single_scanner + ".spdx.json")), context.root_purls)
                details = {"llm_api_calls": 0, "scanner": single_scanner}
            elif method == "sbom_unifier":
                prediction, details = merge(sbom_peers(root, observed, context))
                details.update(llm_api_calls=0, adaptation="Installed filesystem; observed base and all distinct allowed native scanner peers; no source-file enrichment")
            else:
                broker_input = observed
                if method == "unifier_rules":
                    broker_input, _ = merge(sbom_peers(root, observed, context))
                store = EvidenceStore(arm / "evidence")
                sources = prepare_store(root, observed, store, context, condition)
                if {k: {f: v for f, v in source.items() if f != "path"} for k, source in sources.items()} != evidence_binding["sources"]:
                    raise ValueError("Evidence sources changed during a paired case")
                save(arm / "initial_evidence_manifest.json", store.manifest())
                broker = IsolatedBroker(broker_input, store, context, budget, sources, condition == "active", calibration=calibration) if isolated else ToolBroker(
                    broker_input, store, context, budget, sources, condition == "active", calibration)
                try:
                    if method in ("deterministic", "unifier_rules"):
                        details = broker.deterministic() if isolated else deterministic_policy(broker)
                    elif method in ("single_agent", "multi_agent"):
                        if gateway is None or not model:
                            raise ValueError("LLM method needs an authenticated gateway and pinned model")
                        details = run_agent(broker, gateway, model, multi=method == "multi_agent", max_turns=max_turns,
                                            seed=(11, 23, 42)[repetition % 3],
                                            on_event=lambda event: save(arm / f"turn-{event['turn']:03d}.json", event))
                    else:
                        raise ValueError("Unknown method")
                    if isolated:
                        details["isolation"] = broker.audit
                finally:
                    if isolated:
                        broker.close()
                    save(arm / "evidence_manifest.json", store.manifest())
                    store.close()
                prediction = details["verified"]["document"]
            save(arm / "prediction.spdx.json", prediction)
            cdx, conversion = cyclonedx_projection(prediction, context.root_purls)
            save(arm / "recovered.cdx.json", cdx)
            save(arm / "conversion_audit.json", conversion)
            save(arm / "details.json", details)
            # Trusted masking can read the reference before prediction. Prediction
            # workers never see it; scoring occurs only after this seal.
            save(arm / "seal.json", {"spec": spec, "prediction_sha256": digest(arm / "prediction.spdx.json"),
                                     "sealed_at": now(), "oracle_read_before_seal": family != "raw" and mask_origin == "reference",
                                     "oracle_read_role": "CONTROLLED_INPUT_PREPARATION_ONLY" if family != "raw" and mask_origin == "reference" else "EVALUATION_AFTER_SEAL",
                                     "oracle_exposed_to_prediction_worker": False})
            sealed = True
            evaluation = score_after_seal(root, observed, prediction)
            save(arm / "evaluation.json", evaluation)
            save(arm / "coverage.json", coverage(prediction))
            save(arm / "validation.json", validate_native(prediction))
            run_status = details.get("status", "COMPLETE")
            record = {"project": capture["project"]["name"], "partition": capture["project"]["partition"], "status": run_status,
                      "metrics": flat_scores(evaluation), "duration_seconds": time.monotonic() - started,
                      "llm_api_calls": details.get("llm_api_calls", 0), "case": str(out), **spec}
        except Exception as exc:
            if sealed:
                record = {"project": capture["project"]["name"], "partition": capture["project"]["partition"],
                          "status": "SCORING_FAILED", "error": str(exc), "case": str(out), **spec}
                save(arm / "scoring_failure.json", record)
                records.append(record)
                continue
            # An unsuccessful method retains the observed graph; do not improve scores by dropping failures.
            save(arm / "prediction.spdx.json", observed)
            save(arm / "seal.json", {"spec": spec, "prediction_sha256": digest(arm / "prediction.spdx.json"),
                                     "sealed_at": now(), "oracle_read_before_seal": family != "raw" and mask_origin == "reference",
                                     "oracle_exposed_to_prediction_worker": False, "fallback": "OBSERVED_UNCHANGED"})
            fallback_evaluation = score_after_seal(root, observed, observed)
            save(arm / "evaluation.json", fallback_evaluation)
            record = {"project": capture["project"]["name"], "partition": capture["project"]["partition"],
                      "status": "FAILED", "error": str(exc), "case": str(out),
                      "metrics": flat_scores(fallback_evaluation), "fallback": "OBSERVED_UNCHANGED", **spec}
            save(arm / "failure.json", record)
        records.append(record)
        save(arm / "record.json", record)
        print(json.dumps({"project": record["project"], "method": method, "condition": condition,
                          "family": family, "status": record.get("status", "COMPLETE")}), flush=True)
    return {"status": "EXECUTED", "records": records}


def source_comparison(capture_dir, destination):
    """Original source scope, kept separate from installed-graph correctness scoring."""
    root, out = Path(capture_dir), Path(destination)
    out.mkdir(parents=True, exist_ok=True)
    docs = []
    ms = sorted((root / "runtime/source-ms").glob("**/manifest.spdx.json"))
    if ms:
        docs.append(("MS SBOM Tool", load(ms[0])))
    for name, filename in (("Syft", "source-syft.spdx.json"), ("Trivy", "source-trivy.spdx.json")):
        path = root / "runtime" / filename
        if path.exists():
            docs.append((name, load(path)))
    if not docs:
        return {"status": "SOURCE_UNAVAILABLE"}
    prediction, details = merge(docs, root / "source")
    save(out / "unified.spdx.json", prediction)
    stats = {name: coverage(doc) for name, doc in docs}
    stats["sbom-unifier"] = coverage(prediction)
    result = {"status": "EXECUTED", "scope": "SOURCE_FIELD_COVERAGE_ONLY", "coverage": stats,
              "details": details, "github_graph": "UNAVAILABLE_NO_COMMIT_BOUND_SNAPSHOT",
              "correctness": "UNMEASURED_NO_SOURCE_COMPONENT_ORACLE", "source_binding": load(root / "capture.json")["source"]}
    save(out / "comparison.json", result)
    return result


def source_comparison_job(capture_dir, destination):
    try:
        result = source_comparison(capture_dir, destination)
    except Exception as exc:
        result = {"status": "FAILED", "error": str(exc)}
        save(Path(destination) / "failure.json", result)
    return {"project": Path(capture_dir).name, **result}


def summarize(run_root, only_test=True):
    rows = []
    for path in Path(run_root).rglob("records.json"):
        data = load(path)
        rows.extend(data.get("records", []))
    if only_test:
        rows = [r for r in rows if r.get("partition") == "test"]
    comparisons = []
    # Compare like-for-like conditions/budgets, rather than pooling unequal information budgets.
    groups = sorted({(r["condition"], r["budget"], r["family"], r["rate"], r.get("input_origin", "LEGACY_SCANNER_INPUT")) for r in rows})
    for condition, budget, family, rate, origin in groups:
        subset = [r for r in rows if (r["condition"], r["budget"], r["family"], r["rate"], r.get("input_origin", "LEGACY_SCANNER_INPUT")) == (condition, budget, family, rate, origin)]
        for method in ("single_agent", "multi_agent"):
            for baseline in ("sbom_unifier", "unifier_rules", "deterministic"):
                for metric in ("new_metadata_f1", "new_direct_edge_f1"):
                    result = paired_bootstrap(subset, method, baseline, metric)
                    comparisons.append({"method": method, "baseline": baseline, "metric": metric,
                                        **result, "condition": condition, "budget": budget, "family": family, "rate": rate, "input_origin": origin})
    holm(comparisons)
    result = {"status": "MEASURED" if rows else "UNMEASURED_NO_TEST_RESULTS", "records": len(rows),
              "independent_projects": len({r["project"] for r in rows}), "comparisons": comparisons,
              "claim": "NO_SUPERIORITY_CLAIM_AUTOMATICALLY_GENERATED", "downstream": "UNMEASURED_WITHOUT_ADVISORY_SNAPSHOT"}
    save(Path(run_root) / "summary.json", result)
    return result


def run_case_job(parameters, key=None):
    """Process-pool entrypoint; credential lives only in the child/controller memory."""
    from .llm import Gateway
    parameters = dict(parameters)
    client = Gateway(key) if key else None
    try:
        parameters["gateway"] = client
        result = run_case(**parameters)
        save(Path(parameters["destination"]) / "records.json", result)
        return result
    finally:
        if client:
            client.close()
