#!/usr/bin/env python3
"""Scope audit and paired public-evidence interventions; raw legacy artifacts stay immutable."""
from __future__ import annotations

import argparse
from copy import deepcopy
import csv
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research_core import (RunBundle, components, digest, export_scope_csv, graph, load, normalize_sbom,
                           now, reconstructed_document, save, score_application, validate_cdx)
from public_evidence import expand_snapshot, seeds_from_observed
from registry_provider import FrozenRegistryEvidenceProvider
from container_runner import run_container

PILOTS = [
    ("requests", "runs/e4-generator-discrepancy", "runs/e4-generator-discrepancy"),
    ("requests-cache", "runs/pilot-repo-requests-cache", "runs/pilot-repo-requests-cache/reference"),
    ("httpbin", "runs/pilot-repo-httpbin", "runs/pilot-repo-httpbin/reference"),
]
TARGET = {"os_name": "posix", "sys_platform": "linux", "platform_machine": "x86_64", "python_version": "3.11",
          "platform_system": "Linux", "active_extras": []}


def isolated_inference(document, snapshot, image, context=TARGET, mode="baseline"):
    """Copy only four code files, one input, context and frozen public evidence into a no-network container."""
    with tempfile.TemporaryDirectory(prefix="sbom-blind-") as tmp:
        work = Path(tmp)
        code = work / "input"
        code.mkdir()
        output = work / "output"
        output.mkdir()
        for name in ("resolver.py", "registry_provider.py"):
            shutil.copyfile(ROOT / name, code / name)
        shutil.copyfile(ROOT / "scripts/inference_worker.py", code / "inference_worker.py")
        if mode == "ablation":
            shutil.copyfile(ROOT / "information_ablation.py", code / "information_ablation.py")
        evidence = code / "evidence_snapshot"
        evidence.mkdir()
        # Copy manifest-selected metadata only, not downloaded archives or unrelated files.
        manifest = load(Path(snapshot) / "evidence_manifest.json")
        shutil.copyfile(Path(snapshot) / "evidence_manifest.json", evidence / "evidence_manifest.json")
        for entry in manifest["artifacts"]:
            source = (Path(snapshot) / entry["metadata_file"]).resolve()
            if source.parent != Path(snapshot).resolve():
                raise ValueError("Snapshot metadata path escapes its root")
            shutil.copyfile(source, evidence / entry["metadata_file"])
        save(code / "input.cdx.json", document)
        save(code / "context.json", context)
        command = ["docker", "run", "--rm", "--network", "none", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
                   "--memory=2g", "--cpus=2", "--pids-limit=128", "--user", "1000:1000",
                   "-v", f"{code}:/work:ro", "-v", f"{output}:/out:rw", "--entrypoint", "python", image,
                   "/work/inference_worker.py", "--input", "/work/input.cdx.json", "--evidence", "/work/evidence_snapshot",
                   "--context", "/work/context.json", "--out", "/out/predictions.json", "--mode", mode]
        started = now()
        result = run_container(command, timeout=120)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return load(output / "predictions.json"), {"command": command, "started_at": started, "completed_at": now(),
            "network": "none", "oracle_mounted": False, "input_sha256": digest(code / "input.cdx.json"),
            "context_sha256": digest(code / "context.json"), "snapshot_sha256": digest(evidence / "evidence_manifest.json")}


def frozen_snapshot(source, destination):
    destination.mkdir(parents=True)
    manifest = load(source / "evidence_manifest.json")
    for filename in ["evidence_manifest.json"] + [a["metadata_file"] for a in manifest["artifacts"]]:
        shutil.copyfile(source / filename, destination / filename)


def run(out, replay=None, controlled=False):
    out = Path(out).resolve()
    run = RunBundle(out, out.name, purpose="scope audit and counterfactual repair", data_kind="CONTROLLED_SOURCE_MASKING" if controlled else "EMPIRICAL_PILOT",
                    installation_time="UNKNOWN", build_kind="PyPI release installation; not verified Git-commit build")
    try:
        context = load(ROOT / "research/target_context.json")
        originals, normalized, scopes, csv_rows = {}, {}, {}, []
        raw_hashes = {}
        horizons = []
        for project, base, reference in PILOTS:
            for generator, filename in [("syft", "generator_syft.cdx.json"), ("cyclonedx", "generator_cyclonedx.cdx.json")]:
                source = ROOT / base / filename
                raw = load(source)
                if raw.get("metadata", {}).get("timestamp"):
                    horizons.append(raw["metadata"]["timestamp"])
                raw_hashes[str(source.relative_to(ROOT))] = digest(source)
                document, audit = normalize_sbom(raw, root_name=project, bootstrap=("pip", "setuptools"))
                if controlled and generator == "syft":
                    document.pop("dependencies", None)
                originals[project, generator] = source
                normalized[project, generator], scopes[project, generator] = document, audit
                run.artifact(f"{project}/{generator}/normalized.cdx.json", document)
                run.artifact(f"{project}/{generator}/scope.json", audit)
                run.copy(f"{project}/{generator}/original.cdx.json", source)
                csv_rows.extend({"project": project, "generator": generator, **row} for row in audit["components"])
        export_scope_csv(out / "scope_audit.csv", csv_rows)
        context.update(cutoff=min(horizons) if horizons else None,
                       cutoff_status="INSTALLATION_TIME_UNKNOWN; conservative minimum observed SBOM horizon")
        run.artifact("context.json", context)
        snapshot_root = out / "evidence_snapshot"
        snapshot_root.mkdir()
        if replay:
            previous = Path(replay).resolve()
            for regime in ("partial", "wheel", "sdist"):
                frozen_snapshot(previous / "evidence_snapshot" / regime, snapshot_root / regime)
            run.data["replay_of"] = str(previous)
        else:
            frozen_snapshot(ROOT / "fixtures/evidence_snapshot", snapshot_root / "partial")
            expand_snapshot(snapshot_root / "partial", snapshot_root / "wheel", list(normalized.values()), context)
            expand_snapshot(snapshot_root / "wheel", snapshot_root / "sdist", list(normalized.values()), context, allow_sdist=True)
        frozen = {name: digest(ROOT / name) for name in ("resolver.py", "registry_provider.py", "research_core.py", "evaluator.py",
                                                         "scripts/inference_worker.py")}
        records = []
        failures, all_scope_edges = [], []
        for project, base, reference in PILOTS:
            oracle_path = ROOT / reference / "ground_truth.json"
            # Oracle is loaded here in the scoring process only, never in the inference container.
            gold = load(oracle_path)
            document, scope = normalized[project, "syft"], scopes[project, "syft"]
            _, observed_edges = graph(document)
            project_record = {"project": project, "protocol": run.data["protocol"], "regimes": {},
                              "oracle_sha256": digest(oracle_path), "normalized_input_sha256": digest(out / f"{project}/syft/normalized.cdx.json")}
            for regime in ("partial", "wheel", "sdist"):
                snapshot = snapshot_root / regime
                prediction, trace = isolated_inference(document, snapshot, context["image"])
                scores = {arm: score_application(gold, observed_edges, {tuple(e) for e in pred["predicted_edges"]}, scope)
                          for arm, pred in prediction.items()}
                provider = FrozenRegistryEvidenceProvider(snapshot)
                seeds = seeds_from_observed([document])
                covered = sum(provider.get_requirements(f"pkg:pypi/{n}@{v}") is not None for n, v in seeds)
                record = {"baselines": scores, "evidence_coverage": {"observed_parents": len(seeds), "complete_parent_records": covered,
                          "fraction": covered / len(seeds) if seeds else None}, "trace": trace,
                          "snapshot_sha256": digest(snapshot / "evidence_manifest.json")}
                project_record["regimes"][regime] = record
                path = f"{project}/{regime}"
                run.artifact(path + "/predictions.json", prediction)
                run.artifact(path + "/evaluation.json", scores)
                run.artifact(path + "/evidence.json", {"candidates": prediction["B3"]["G_candidate"],
                    "unresolved": prediction["B3"].get("unresolved", []), "snapshot_sha256": record["snapshot_sha256"], "trace": trace})
                reconstruction = reconstructed_document(prediction["B3"]["G_reconstructed"])
                run.artifact(path + "/reconstructed.cdx.json", reconstruction)
                schema = validate_cdx(reconstruction)
                run.artifact(path + "/schema_validation.json", schema)
                if not schema["valid"]:
                    raise ValueError(f"Invalid reconstruction for {project}/{regime}; see schema_validation.json")
                all_scope_edges.extend({"project": project, "regime": regime, "baseline": arm, **edge}
                                       for arm, score in scores.items() for edge in score["edge_audit"])
            _, control_edges = graph(normalized[project, "cyclonedx"])
            project_record["positive_control"] = score_application(gold, set(), control_edges, scopes[project, "cyclonedx"])
            before = {tuple(e) for e in project_record["regimes"]["partial"]["baselines"]["B3"]["missed_edges"]}
            middle = {tuple(e) for e in project_record["regimes"]["wheel"]["baselines"]["B3"]["missed_edges"]}
            after = {tuple(e) for e in project_record["regimes"]["sdist"]["baselines"]["B3"]["missed_edges"]}
            project_record["interventions"] = {"recovered_with_wheel": sorted(before - middle), "recovered_with_sdist": sorted(middle - after),
                                                 "still_missing": sorted(after), "newly_missing_after_repair": sorted(after - before)}
            for edge in sorted(before | after):
                recovered = edge not in after
                failures.append({"project": project, "source": edge[0], "target": edge[1],
                                 "historical_fn": edge in before, "recovered": recovered,
                                 "intervention": "wheel" if edge not in middle else "sdist" if recovered else None,
                                 "feasibility_category": "B" if recovered else "UNRESOLVED",
                                 "failure_taxonomy": "D" if recovered else "UNRESOLVED",
                                 "interpretation": "Additional public evidence sufficient in this paired run" if recovered else "Do not infer impossibility or algorithm correctness"})
            records.append(project_record)
            for generator in ("syft", "cyclonedx"):
                run.artifact(f"{project}/{generator}/schema_validation.json", validate_cdx(normalized[project, generator]))
        assert frozen == {name: digest(ROOT / name) for name in frozen}, "Engine changed during intervention"
        assert raw_hashes == {name: digest(ROOT / name) for name in raw_hashes}, "Raw generator input changed"
        historical = list(csv.DictReader((ROOT / "fn_root_cause_report.csv").open()))
        historical_edges = {(r["project"], r["parent_purl"], r["child_purl"]): r["edge_id"] for r in historical}
        for row in failures:
            row["historical_edge_id"] = historical_edges.get((row["project"], row["source"], row["target"]))
        run.artifact("counterfactual_evidence_repair.json", {"schema_version": "counterfactual-v1", "protocol": run.data["protocol"],
            "data_kind": run.data["context"]["data_kind"],
            "mask_policy": "Remove all dependency declarations, keep all observed eligible identities; deterministic" if controlled else "NONE; all resolvable raw dependency edges preserved",
            "frozen_code": frozen, "raw_input_hashes": raw_hashes, "projects": records,
            "legacy_caveat": "Old evidence snapshot selection was hard-coded; new acquisition uses observed identities only",
            "historical_fn_count": len(historical), "historical_ids_matched": sorted(r["historical_edge_id"] for r in failures if r["historical_edge_id"]),
            "failure_decomposition": failures, "security_metrics": "UNMEASURED: no new advisory/exploitability experiment",
            "claim_limit": "Paired deterministic evidence repair on three pilots; not proof of zero algorithmic failures"})
        run.artifact("edge_scope_audit.json", all_scope_edges)
        run.finish()
        print(json.dumps({"out": str(out), "projects": len(records), "counterfactual_edges": len(failures)}))
    except Exception as exc:
        run.finish("BLOCKED", technical_cause=str(exc))
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--replay", type=Path, help="Use previously frozen snapshots; no public queries")
    parser.add_argument("--controlled", action="store_true", help="Separate controlled source-declaration masking; NEVER label as generator omissions")
    args = parser.parse_args()
    run(args.out, args.replay, args.controlled)
