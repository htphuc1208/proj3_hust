#!/usr/bin/env python3
"""Read-only, sealed raw-track audit; no inference, acquisition, or policy tuning.

An audit may describe a completion-time-censored checkpoint. --wait waits for
the exact frozen raw matrix before taking its snapshot. All derived outputs
and reference copies go into a fresh directory, outside the prediction run.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from email.parser import BytesParser
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from packageurl import PackageURL

from research_core import digest, load, now
from sbom_recovery.campaign import flat_scores, score_after_seal
from sbom_recovery.contracts import TargetContext
from sbom_recovery.evidence import marker_value
from sbom_recovery.formats import NativeDocument, package_purl, sha
from sbom_recovery.freeze import freeze
from sbom_recovery.metrics import graph_facts, paired_bootstrap, holm, risk_coverage
from sbom_recovery.reporting import aggregate, read_records
from sbom_recovery.security import score_campaign_security
from sbom_recovery.storage import save, save_bytes
from scripts.export_interim_sbom_report import (
    METHODS, completed_project_rows, copy_snapshot_file, csv_file, instant,
    paired_case, take_snapshot,
)


def resolve_input(value):
    path = Path(value)
    return path.resolve() if path.is_absolute() else (ROOT / path).resolve()


def expected_matrix(study):
    plan = load(study / "plan.json")
    cohort_path = resolve_input(plan["cohort"])
    if digest(cohort_path) != plan["cohort_sha256"]:
        raise ValueError("Frozen cohort changed")
    projects = [p["name"] for p in load(cohort_path)["projects"] if p["partition"] == "test"]
    if len(projects) != len(set(projects)):
        raise ValueError("Duplicate held-out project")
    spec = next(s for s in plan["stages"] if s["name"] == "test/raw")
    expected = {(p, c, b, r) for p in projects for c in spec["conditions"]
                for b in spec["budgets"] for r in range(spec["repetitions"])}
    if len(expected) != spec["expected_cases"] or set(spec["methods"]) != set(METHODS):
        raise ValueError("Unsupported frozen raw allocation")
    return expected, plan, spec


def matrix_progress(study):
    expected, plan, spec = expected_matrix(study)
    found = set()
    unscored = []
    for path in sorted((study / "test/raw").rglob("records.json")):
        rows = load(path).get("records", [])
        paired_case(rows)
        row = rows[0]
        if row["rate"] != 0 or row["mask_seed"] != spec["seeds"][0]:
            raise ValueError("Unexpected raw seed/rate")
        key = (row["project"], row["condition"], row["budget"], row["repetition"])
        if any(r["project"] != row["project"] for r in rows):
            raise ValueError("Mixed projects in a paired case")
        if key not in expected or key in found:
            raise ValueError("Unexpected or duplicate raw case: " + str(key))
        for r in rows:
            if not (path.parent / r["method"] / "evaluation.json").exists() or "metrics" not in r:
                unscored.append({"case": str(path.parent), "method": r["method"]})
        found.add(key)
    return {"expected": len(expected), "recorded": len(found), "missing": len(expected - found),
            "unscored": unscored, "complete": found == expected and not unscored}, plan, spec


def context_for(capture):
    info = load(capture / "capture.json")
    context = TargetContext.model_validate(load(capture / "context.json"))
    return context.model_copy(update={
        "evidence_cutoff": info["historical_resolution_horizon"],
        "root_purls": context.root_purls or [
            f"pkg:pypi/{info['project']['name']}@{info['project']['version']}"],
    })


def metadata_catalog(capture, binding, context):
    """Use only allowed, content-bound target sources; never oracle extras/labels.

    This is evaluation-side evidence inspection, not a new prediction. Unknown
    marker variables remain unknown instead of falling back to the audit host.
    """
    catalog = {}
    diagnostics = []
    total = 0
    for source_id, source in sorted(binding["sources"].items()):
        if source["kind"] != "target_metadata":
            continue
        total += 1
        description = source["description"]
        if not description.startswith("target:"):
            raise ValueError("Unrecognized target source")
        relative = Path(description.removeprefix("target:"))
        target_root = (capture / "runtime/target").resolve()
        path = (target_root / relative).resolve()
        if relative.is_absolute() or not path.is_relative_to(target_root):
            raise ValueError("Evidence path escapes target")
        raw = path.read_bytes()
        if sha({"raw_hex": raw.hex()}) != source["content_binding"]:
            raise ValueError("Allowed target metadata changed: " + str(path))
        if instant(source["available_at"]) > instant(context.evidence_cutoff):
            diagnostics.append({"source_id": source_id, "reason": "AFTER_EVIDENCE_CUTOFF"})
            continue
        message = BytesParser().parsebytes(raw)
        if not message.get("Name") or not message.get("Version"):
            diagnostics.append({"source_id": source_id, "reason": "INVALID_METADATA_IDENTITY"})
            continue
        name = canonicalize_name(message["Name"])
        purl = f"pkg:pypi/{name}@{message['Version']}"
        item = {"source_id": source_id, "source_path": str(path), "source_sha256": hashlib.sha256(raw).hexdigest(),
                "name": name, "version": message["Version"], "purl": purl, "requirements": [], "extras": set()}
        for text in message.get_all("Requires-Dist", []):
            try:
                requirement = Requirement(text)
            except InvalidRequirement:
                diagnostics.append({"source_id": source_id, "reason": "INVALID_REQUIREMENT"})
                continue
            item["requirements"].append((text, requirement))
        if purl in catalog:
            diagnostics.append({"source_id": source_id, "reason": "DUPLICATE_METADATA_IDENTITY"})
        catalog[purl] = item
    by_name = defaultdict(list)
    for purl, item in catalog.items():
        by_name[item["name"]].append(item)
        item["extras"].update(canonicalize_name(x) for x in context.extras_by_purl.get(purl, []))
        if purl in context.root_purls:
            item["extras"].update(canonicalize_name(x) for x in context.active_extras)
    # Compute both known and possible activation. Unknown markers on a different
    # dependency may activate an extra transitively; they cannot justify a false
    # "inactive" attribution just because known activation did not reach it.
    for item in catalog.values():
        item["possible_extras"] = set(item["extras"])
    for state, conservative in (("extras", False), ("possible_extras", True)):
        while True:
            changed = False
            for item in catalog.values():
                for _, req in item["requirements"]:
                    active = marker_value(req, context, item[state])
                    if active is False or (not conservative and (active is not True or req.url)):
                        continue
                    matches = []
                    for candidate in by_name[canonicalize_name(req.name)]:
                        try:
                            if req.url or req.specifier.contains(Version(candidate["version"]), prereleases=True):
                                matches.append(candidate)
                        except InvalidVersion:
                            diagnostics.append({"source_id": candidate["source_id"], "reason": "INVALID_VERSION"})
                    if not conservative and len(matches) != 1:
                        continue
                    for match in matches:
                        before = len(match[state])
                        match[state].update(canonicalize_name(x) for x in req.extras)
                        changed |= len(match[state]) != before
            if not changed:
                break
    return catalog, {"sources": total, "parsed": len(catalog), "complete": total == len(catalog) and not diagnostics,
                     "diagnostics": diagnostics, "extras_source": "ALLOWED_CONTEXT_AND_TARGET_METADATA_ONLY"}


def edge_context(edge, catalog, catalog_audit, context):
    source, target = edge
    parent = catalog.get(source)
    result = {"category": "UNRESOLVED", "attribution": "UNRESOLVED_NO_CAUSAL_EVIDENCE",
              "matching_requirements": [], "parent_metadata_sha256": None, "parent_source_id": None,
              "effective_extras": [], "possible_extras": [], "context_sha256": sha(context.model_dump())}
    if parent is None:
        result["attribution"] = "PARENT_METADATA_UNAVAILABLE"
        return result
    result.update(parent_metadata_sha256=parent["source_sha256"], parent_source_id=parent["source_id"],
                  effective_extras=sorted(parent["extras"]), possible_extras=sorted(parent["possible_extras"]))
    target_name = canonicalize_name(PackageURL.from_string(target).name)
    for text, requirement in parent["requirements"]:
        if canonicalize_name(requirement.name) != target_name:
            continue
        active = marker_value(requirement, context, parent["extras"])
        result["matching_requirements"].append({"requirement": text, "active": active,
            "active_with_possible_extras": marker_value(requirement, context, parent["possible_extras"])})
    matches = result["matching_requirements"]
    if catalog_audit["complete"] and matches and all(r["active_with_possible_extras"] is False for r in matches):
        result.update(category="C", attribution="ALL_MATCHING_DECLARATIONS_INACTIVE_IN_CAPTURED_CONTEXT")
    elif any(r["active"] is None for r in matches):
        result["attribution"] = "CONTEXT_UNCERTAIN_MARKER_VARIABLE"
    elif any(r["active"] is False and r["active_with_possible_extras"] is not False for r in matches):
        result["attribution"] = "CONTEXT_UNCERTAIN_TRANSITIVE_EXTRA_ACTIVATION"
    elif not catalog_audit["complete"]:
        result["attribution"] = "INCOMPLETE_ALLOWED_METADATA_CATALOG"
    return result


def error_class(message):
    """Export bounded categories, not raw provider/error text or credentials."""
    text = str(message).lower()
    if "timeout" in text or "timed out" in text:
        return "TIMEOUT"
    if "connect" in text:
        return "CONNECTION"
    if "truncat" in text or "finish_reason" in text and "length" in text:
        return "TRUNCATED_RESPONSE"
    http_status = re.search(r"\bhttp\s+([45]\d\d)\b", text)
    if http_status:
        return "HTTP_" + http_status.group(1)
    if "json" in text or "schema" in text or "argument" in text:
        return "RESPONSE_FORMAT"
    return "OTHER_RECORDED_ERROR" if text else "UNRECORDED"


def edge_rows(row, evaluation, observed, prediction, details, catalog, catalog_audit, context, manifest=None):
    observed_edges = graph_facts(observed)[1]
    predicted = NativeDocument(prediction)
    purls = {ref: package_purl(item, predicted.format) for ref, item in predicted.packages().items()}
    policy_reasons = defaultdict(set)
    for state in ("accepted", "supported", "rejected"):
        for item in details.get("verified", {}).get(state, []):
            proposal = item.get("proposal", {})
            if proposal.get("operation") != "add_dependency":
                continue
            edge = proposal_edge(proposal, purls)
            policy_reasons[edge].add(state + ":" + item.get("reason", item.get("status", "UNRECORDED")))
    result = []
    for direction, field in (("FP", "false_positive_edges"), ("FN", "missed_edges")):
        for fact in evaluation[field]:
            edge = tuple(fact)
            attribution = edge_context(edge, catalog, catalog_audit, context)
            if direction == "FN":
                attribution.update(category="UNRESOLVED", attribution="MISSING_REFERENCE_EDGE_CAUSE_UNRESOLVED")
            acquired = {r["sha256"] for r in (manifest or {}).get("records", [])
                        if r.get("kind") == "target_metadata" and r.get("authority") == "VERIFIED_TARGET"
                        and r.get("target_id") == context.target_id
                        and r.get("available_at") and instant(r["available_at"]) <= instant(context.evidence_cutoff)}
            parent, target = catalog.get(edge[0]), catalog.get(edge[1])
            result.append({k: row[k] for k in ("project", "condition", "method", "repetition", "status")} | {
                "direction": direction, "source_purl": edge[0], "target_purl": edge[1],
                "present_in_observation": edge in observed_edges,
                "origin": ("INHERITED_FROM_OBSERVATION" if edge in observed_edges else "INTRODUCED_BY_METHOD")
                          if direction == "FP" else "MISSING_IN_PREDICTION",
                "policy_reasons": sorted(policy_reasons[edge]),
                "parent_metadata_permitted": parent is not None, "target_metadata_permitted": target is not None,
                "parent_metadata_acquired": parent["source_sha256"] in acquired if parent and manifest is not None else None,
                "target_metadata_acquired": target["source_sha256"] in acquired if target and manifest is not None else None,
                **attribution})
    return result


def proposal_edge(proposal, identities):
    source, target = proposal.get("subject"), proposal.get("value")
    return (identities.get(source) if isinstance(source, str) else None,
            identities.get(target) if isinstance(target, str) else None)


def verify_manifest_binding(manifest, details):
    expected = details.get("isolation", {}).get("final_evidence_sha256")
    if expected is None or sha(manifest) != expected:
        raise ValueError("Saved acquisition manifest lacks its worker binding")
    for record in manifest["records"]:
        identity = {k: v for k, v in record.items() if k not in {"acquired_at", "evidence_id"}}
        if sha(identity) != record["evidence_id"]:
            raise ValueError("Evidence record identity digest mismatch")


def audit_arm(capture, case, row, context):
    arm = case / row["method"]
    if sha(context.model_dump()) != row["context_sha256"]:
        raise ValueError("Captured context differs from sealed case")
    observation, prediction = load(case / "input.spdx.json"), load(arm / "prediction.spdx.json")
    evaluation = load(arm / "evaluation.json")
    current = score_after_seal(capture, observation, prediction)
    if current != evaluation:
        raise ValueError("Stored evaluation differs from independent re-scoring: " + str(arm))
    if row["metrics"] != flat_scores(current):
        raise ValueError("Recorded scores differ from re-scored prediction")
    return observation, prediction, evaluation


def numeric_summary(values):
    values = [v for v in values if isinstance(v, (int, float))]
    return {"n": len(values), "mean": statistics.mean(values) if values else None,
            "median": statistics.median(values) if values else None, "sum": sum(values)}


def summarize_edge_errors(errors):
    groups = defaultdict(list)
    for error in errors:
        groups[(error["condition"], error["method"], error["direction"])].append(error)
    output = []
    for (condition, method, direction), rows in sorted(groups.items()):
        output.append({"condition": condition, "method": method, "direction": direction,
                       "error_occurrences": len(rows),
                       "distinct_project_edges": len({(r["project"], r["source_purl"], r["target_purl"]) for r in rows}),
                       "projects_with_errors": len({r["project"] for r in rows}),
                       "origin_counts": dict(Counter(r["origin"] for r in rows)),
                       "category_counts": dict(Counter(r["category"] for r in rows)),
                       "attribution_counts": dict(Counter(r["attribution"] for r in rows))})
    return output


def additive_bound(observed_evaluation, predicted_evaluation, observation, prediction):
    """Evaluation-only oracle ceiling when existing edge identities are preserved.

    Recovering all labeled reference edges cannot remove inherited known FP.
    Unknown labels are excluded by the original evaluator, never made negative.
    This bound is not a prediction and is unavailable to acquisition policies.
    """
    observed_edges, predicted_edges = graph_facts(observation)[1], graph_facts(prediction)[1]
    truth_count = observed_evaluation["whole_edges"]["tp"] + observed_evaluation["whole_edges"]["fn"]
    inherited = observed_evaluation["whole_edges"]["fp"]
    denominator = 2 * truth_count + inherited
    bound = 2 * truth_count / denominator if denominator else None
    actual = predicted_evaluation["whole_edges"]["f1"]
    preserves = observed_edges.issubset(predicted_edges)
    return {"known_reference_edges": truth_count, "inherited_known_fp": inherited,
            "bound_f1": bound, "actual_f1": actual, "existing_edge_identities_preserved": preserves,
            "at_bound": preserves and bound is not None and actual is not None and abs(bound-actual) < 1e-12,
            "interpretation": "ORACLE_EVALUATION_BOUND_ONLY; assumes fixed edge identities and no retractions"}


def freeze_analysis(destination):
    freeze(destination)
    manifest = load(destination / "source_manifest.json")
    for name in ("scripts/audit_raw_sbom_study.py", "scripts/export_interim_sbom_report.py",
                 "research/NEXT_EXPERIMENT.md", "configs/evidence-acquisition-v1.json"):
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        manifest["files"][name] = digest(target)
    manifest["sha256"] = sha(manifest["files"])
    save(destination / "source_manifest.json", manifest)
    return manifest["sha256"]


def export(study, out, require_complete=False):
    study, out = Path(study).resolve(), Path(out).resolve()
    if out == study or out.is_relative_to(study):
        raise ValueError("Audit output must be outside the frozen prediction run")
    progress, plan, spec = matrix_progress(study)
    if require_complete and not progress["complete"]:
        raise ValueError("Raw matrix is not fully executed and scored")
    out.mkdir(parents=True, exist_ok=False)
    save(out / "audit-progress.json", {"phase": "TAKING_SNAPSHOT", "updated_at": now()})
    cutoff = datetime.now(timezone.utc)
    source_sha = freeze_analysis(out / "source_bundle")
    snapshot, settings = take_snapshot(study, out / "snapshot", cutoff)
    expected, _, _ = expected_matrix(study)
    included = {(r["project"], r["condition"], spec["budgets"][0], r["repetition"]) for r in snapshot["included_cases"]}
    complete = included == expected and not snapshot["omitted_cases"]
    if require_complete and not complete:
        raise ValueError("A completed raw audit requires the full sealed matrix")
    save(out / "snapshot-manifest.json", snapshot)
    inputs = {}
    input_paths = {
        "plan.json": study / "plan.json", "model-selection.json": study / "model-selection.json",
        "state-at-audit.json": study / "state.json", "raw-campaign-at-audit.json": study / "test/raw/campaign.json",
        "cohort.json": resolve_input(plan["cohort"]),
        "osv-snapshot.json": resolve_input(plan["snapshot"]),
    }
    uses_conformal = plan.get("schema_version") != "agent-study-v3-no-conformal"
    if uses_conformal:
        input_paths["conformal.json"] = study / "calibration/conformal.json"
    for name, src in input_paths.items():
        inputs[str(src)] = {"copy": str(out / "inputs" / name),
                            "sha256": copy_snapshot_file(src, out / "inputs" / name)}
    if digest(out / "inputs/osv-snapshot.json") != plan["snapshot_sha256"]:
        raise ValueError("Frozen OSV snapshot changed")
    frozen_files = load(study / "source_bundle/source_manifest.json")["files"]
    if sha(frozen_files) != plan["source_sha256"] or settings["source_sha256"] != plan["source_sha256"]:
        raise ValueError("Frozen prediction source manifest differs from plan")
    for name, checksum in frozen_files.items():
        if digest(study / "source_bundle" / name) != checksum:
            raise ValueError("Frozen prediction source changed: " + name)
    # The episode binds package-module bytes, whereas the plan binds the full
    # source bundle. Calibration uses canonical JSON content, not file bytes.
    implementation_sha = sha({Path(name).name: checksum for name, checksum in frozen_files.items()
                              if Path(name).parent == Path("sbom_recovery") and name.endswith(".py")})
    calibration_sha = sha(load(out / "inputs/conformal.json")) if uses_conformal else None
    captures = resolve_input(settings["captures"])
    references = {}
    extra_hashes = {}
    errors, failures, rows, proposal_labels, bounds = [], [], [], [], []
    catalog_cache, contexts = {}, {}
    for case_file in sorted((out / "snapshot").rglob("records.json")):
        case = case_file.parent
        original_case = study / "test/raw" / case.relative_to(out / "snapshot")
        records = load(case_file)["records"]
        project = records[0]["project"]
        capture = captures / project
        save(out / "audit-progress.json", {"phase": "RESCORING", "project": project,
            "recomputed_arms": len(rows), "updated_at": now()})
        if project not in contexts:
            contexts[project] = context_for(capture)
            references[project] = {}
            for name in ("context.json", "capture.json", "oracle/installed_reference.cdx.json",
                         "oracle/installed_reference.json", "oracle/installed_field_labels.json",
                         "oracle/installed_reference_provenance.json", "oracle/pip_inspect.json", "oracle/install_report.json"):
                path = capture / name
                references[project][name] = {"original": str(path), "copy": str(out / "references" / project / name),
                                            "sha256": copy_snapshot_file(path, out / "references" / project / name)}
            provenance = load(capture / "oracle/installed_reference_provenance.json")
            if provenance["pip_inspect_sha256"] != digest(capture / "oracle/pip_inspect.json") or \
               provenance["installation_report_sha256"] != digest(capture / "oracle/install_report.json"):
                raise ValueError("Reference source provenance changed")
        context = contexts[project]
        binding = load(case / "evidence_binding.json")
        cache_key = (project, sha(binding))
        if cache_key not in catalog_cache:
            catalog_cache[cache_key] = metadata_catalog(capture, binding, context)
            for item in catalog_cache[cache_key][0].values():
                src = Path(item["source_path"])
                target = out / "allowed-evidence/blobs" / item["source_sha256"]
                if not target.exists():
                    copy_snapshot_file(src, target)
                extra_hashes[str(src)] = item["source_sha256"]
        catalog, catalog_audit = catalog_cache[cache_key]
        save(case / "allowed-metadata-audit.json", {**catalog_audit, "bindings": [
            {k: item[k] for k in ("purl", "source_id", "source_path", "source_sha256")} |
            {"effective_extras": sorted(item["extras"]), "possible_extras": sorted(item["possible_extras"])} for item in catalog.values()]})
        for row in records:
            if row["implementation_sha256"] != implementation_sha:
                raise ValueError("Case implementation differs from frozen study source")
            if row.get("calibration_sha256") != calibration_sha:
                raise ValueError("Case calibration differs from frozen calibration artifact")
            arm = case / row["method"]
            live_arm = original_case / row["method"]
            for name in ("evidence_manifest.json", "initial_evidence_manifest.json"):
                path = live_arm / name
                if path.exists():
                    extra_hashes[str(path)] = copy_snapshot_file(path, arm / name)
            observation, prediction, evaluation = audit_arm(capture, case, row, context)
            if row["method"] == "deterministic":
                bounds.append({k: row[k] for k in ("project", "condition", "repetition")} |
                              additive_bound(load(case / "observed/evaluation.json"), evaluation, observation, prediction))
            details = load(arm / "details.json") if (arm / "details.json").exists() else {}
            manifest_path = arm / "evidence_manifest.json"
            evidence_manifest = load(manifest_path) if manifest_path.exists() else None
            if evidence_manifest is not None:
                verify_manifest_binding(evidence_manifest, details)
            errors.extend(edge_rows(row, evaluation, observation, prediction, details, catalog, catalog_audit, context, evidence_manifest))
            transcript_errors = [t["error"] for t in details.get("transcript", []) if isinstance(t, dict) and t.get("error")]
            failures.append({k: row[k] for k in ("project", "condition", "method", "repetition", "status")} | {
                "terminal_error_class": error_class(transcript_errors[-1] if transcript_errors else row.get("error", ""))
                                        if row["status"] != "COMPLETE" else None,
                "error_events": len(transcript_errors),
                "accepted_changes": len(details.get("verified", {}).get("accepted", [])),
                "acquire_calls": sum(t.get("tool", t.get("name")) == "acquire" for t in details.get("tool_trace", [])),
                "duration_seconds": row.get("duration_seconds"), "llm_api_calls": row.get("llm_api_calls"),
                "reported_tokens": details.get("tokens", {}).get("total_tokens"),
                "unknown_usage_attempts": details.get("tokens", {}).get("unknown_usage_attempts"),
                "validation_valid": load(arm / "validation.json").get("valid") if (arm / "validation.json").exists() else None})
            # Inspect evidence-gate decisions for edges only; unknown reference
            # parents stay unlabeled. These are ranks, not model probabilities.
            idx = NativeDocument(prediction).packages()
            identity = {r: package_purl(item, "spdx") for r, item in idx.items()}
            truth = graph_facts(load(capture / "oracle/installed_reference.cdx.json"))[1]
            unknown = set(map(tuple, evaluation.get("unknown_label_edges", [])))
            unresolved_names = {u.get("parent") for u in load(capture / "oracle/installed_reference.json").get("unresolved", [])}
            for state, score in (("accepted", 1.), ("supported", .5), ("rejected", 0.)):
                for item in details.get("verified", {}).get(state, []):
                    p = item.get("proposal", {})
                    if p.get("operation") != "add_dependency":
                        continue
                    fact = proposal_edge(p, identity)
                    correct = None
                    if all(fact) and fact not in unknown:
                        correct = fact in truth
                        if not correct and canonicalize_name(PackageURL.from_string(fact[0]).name) in unresolved_names:
                            correct = None
                    proposal_labels.append({"project": project, "method": row["method"], "condition": row["condition"],
                                            "repetition": row["repetition"], "state": state, "score": score,
                                            "correct": correct, "proposal_sha256": sha(p)})
            rows.append(row)
    security = score_campaign_security(out / "snapshot", captures, out / "inputs/osv-snapshot.json")
    scored, provenance = read_records(out / "snapshot")
    summary = aggregate(scored)
    csv_file(out / "report/metrics.csv", summary)
    csv_errors = [{k: json.dumps(v, sort_keys=True) if isinstance(v, (list, dict)) else v for k, v in r.items()} for r in errors]
    csv_file(out / "report/edge-errors.csv", csv_errors)
    csv_file(out / "report/execution.csv", failures)
    csv_file(out / "report/additive-bound.csv", bounds)
    csv_file(out / "report/completed-project-metrics.csv", aggregate(completed_project_rows(scored, settings["repetitions"])))
    edge_summary = summarize_edge_errors(errors)
    save(out / "report/edge-error-summary.json", {
        "unit": "Arm/edge error occurrences; distinct_project_edges deduplicates repetitions",
        "category_C": "All matching target declarations inactive under allowed context and propagated extras",
        "causality_limit": "Establishes an artifact/context mismatch, not the internal cause in the scanner implementation",
        "groups": edge_summary})
    comparisons = []
    for condition in sorted({r["condition"] for r in scored}):
        subset = [r for r in scored if r["condition"] == condition]
        for method in ("single_agent", "multi_agent"):
            for baseline in ("deterministic", "sbom_unifier", "single_scanner"):
                for metric in ("new_direct_edge_f1", "whole_direct_edge_f1", "new_metadata_f1"):
                    comparisons.append({"condition": condition, **paired_bootstrap(subset, method, baseline, metric)})
    save(out / "report/paired-comparisons.json", {
        "role": "COMPLETED_RAW_TRACK_ANALYSIS" if complete else "EXPLORATORY_COMPLETION_TIME_CENSORED",
        "thresholds_models_policies_retuned": False, "bootstrap_unit": "project", "comparison_family": "all exported raw contrasts",
        "comparisons": holm(comparisons)})
    risks = []
    gate_groups = {(r["method"], r["condition"]) for r in scored
                   if r["method"] in ("deterministic", "unifier_rules", "single_agent", "multi_agent")}
    for method, condition in sorted(gate_groups):
        labels = [p for p in proposal_labels if (p["method"], p["condition"]) == (method, condition)]
        risks.append({"method": method, "condition": condition,
                      "status": "OBSERVED_EDGE_PROPOSALS" if labels else "UNMEASURED_NO_EDGE_PROPOSALS",
                      **risk_coverage(labels)})
    save(out / "report/risk-coverage.json", {"population": "Edge proposals with resolvable endpoint identities; unknown labels retained separately",
        "coverage_denominator": "Known labeled edge proposal occurrences, including repeats",
        "scores": "Evidence-gate ranks 1/.5/0, not calibrated probabilities; no exchangeability guarantee",
        "groups": risks})
    save(out / "report/edge-proposal-labels.json", proposal_labels)
    security_data = load(out / "snapshot/security_assessment.json")
    security_groups = defaultdict(list)
    for r in security_data["records"]:
        condition = Path(r["case"]).relative_to(out / "snapshot").parts[1]
        security_groups[(condition, r["method"])].append(r)
    security_summary = []
    for (condition, method), items in sorted(security_groups.items()):
        eligible = {r["project"] for r in items if r["reference_population"] > 0}
        security_summary.append({"condition": condition, "method": method, "eligible_projects": sorted(eligible),
            "n_eligible_projects": len(eligible), "n_projects": len({r["project"] for r in items}),
            "newly_recovered_project_package_advisories": len({(r["project"], *fact) for r in items for fact in r["newly_recovered"]})})
    save(out / "report/security-summary.json", {"groups": security_summary, "assessment": "RETROSPECTIVE_LEVEL_1",
        "triage_delta": "UNMEASURED", "false_assurance_reduction": "UNMEASURED", "exploitability": "UNMEASURED"})
    execution_summary = []
    for condition, method in sorted({(r["condition"], r["method"]) for r in failures}):
        items = [r for r in failures if (r["condition"], r["method"]) == (condition, method)]
        execution_summary.append({"condition": condition, "method": method, "arms": len(items),
            "status_counts": dict(Counter(r["status"] for r in items)),
            "terminal_error_counts": dict(Counter(r["terminal_error_class"] for r in items if r["terminal_error_class"])),
            "duration_seconds": numeric_summary([r["duration_seconds"] for r in items]),
            "reported_tokens": numeric_summary([r["reported_tokens"] for r in items]),
            "unknown_usage_attempts": sum(r["unknown_usage_attempts"] or 0 for r in items),
            "monetary_cost": "UNMEASURED_NO_VERIFIED_PRICING"})
    save(out / "report/execution-summary.json", execution_summary)
    fixed_first = [e for e in errors if e["method"] == "deterministic" and e["condition"] == "fixed" and e["repetition"] == 0]
    result = {"schema_version": "raw-study-audit-v1", "status": "COMPLETE_RAW_TRACK" if complete else "INTERIM_RAW_TRACK",
        "created_at": now(), "cutoff": cutoff.isoformat(), "paired_cases": len(included), "expected_cases": len(expected),
        "projects": len({r["project"] for r in scored}), "recomputed_arms": len(scored), "llm_api_calls_by_audit": 0,
        "original_predictions_modified": False, "frozen_study_policy_modified": False,
        "analysis_source_sha256": source_sha, "deterministic_fixed_first_repetition": {
            "projects": len({r["project"] for r in rows if r["method"] == "deterministic" and r["condition"] == "fixed" and r["repetition"] == 0}),
            "FP": sum(e["direction"] == "FP" for e in fixed_first), "FN": sum(e["direction"] == "FN" for e in fixed_first),
            "inherited_FP": sum(e["direction"] == "FP" and e["present_in_observation"] for e in fixed_first),
            "categories": dict(Counter(e["category"] for e in fixed_first))},
        "fixed_additive_bound": {"cases": sum(r["condition"] == "fixed" for r in bounds),
            "cases_at_bound": sum(r["condition"] == "fixed" and r["at_bound"] for r in bounds),
            "cases_preserving_edge_identities": sum(r["condition"] == "fixed" and r["existing_edge_identities_preserved"] for r in bounds)},
        "report": str(out / "report/REPORT.md"), "superiority": "REQUIRES_PAIRED_METRICS_AND_VALIDITY_REVIEW"}
    save(out / "provenance.json", {"analysis_source_sha256": source_sha, "inputs": inputs,
        "references": references, "additional_artifact_sha256": extra_hashes, "snapshot_record_sha256": provenance,
        "boundary": "Evaluation-only audit may inspect independent labels after original prediction seals; no output enters inference"})
    write_report(out, result, summary, edge_summary, execution_summary, security_summary)
    plots(out, summary, edge_summary, execution_summary, risks, result)
    save(out / "result.json", result)
    outputs = {str(p.relative_to(out)): digest(p) for p in sorted((out / "report").glob("*")) if p.is_file()}
    save(out / "report-manifest.json", {"files": outputs, "sha256": sha(outputs)})
    save(out / "audit-progress.json", {"phase": "EXPORTED", "recomputed_arms": len(rows), "updated_at": now()})
    return result


def fmt(value):
    return "undefined" if value is None else f"{value:.4f}"


def write_report(out, result, metrics, edge_summary, execution, security):
    table = "\n".join(f"| {r['condition']} | {r['method']} | {r['cases']} | {fmt(r['whole_direct_edge_precision'])} | "
        f"{fmt(r['whole_direct_edge_recall'])} | {fmt(r['whole_direct_edge_f1'])} | {fmt(r['new_direct_edge_f1'])} | "
        f"{r['whole_direct_edge_f1_n_projects']} | {r['incomplete']} |" for r in metrics)
    panel = result["deterministic_fixed_first_repetition"]
    model_errors = sum(r["status_counts"].get("MODEL_ERROR", 0) for r in execution if r["method"] == "single_agent")
    single_n = sum(r["arms"] for r in execution if r["method"] == "single_agent")
    census = "The entire frozen raw matrix is included." if result["status"] == "COMPLETE_RAW_TRACK" else (
        "This checkpoint is censored by completion time. Later repetitions and slow cases are underrepresented; intervals are exploratory.")
    eligible = sorted({p for r in security for p in r["eligible_projects"]})
    text = f"""# M2.5 raw study: deterministic control, agent reliability, and edge-error audit

Generated {result['created_at']}. **{result['status']}**: {result['paired_cases']}/{result['expected_cases']} paired cases, {result['projects']} projects, {result['recomputed_arms']} independently re-scored arms. {census}

## Context & Problem Formulation

The evaluated graph contains top-level installed Python distributions and environment-conditioned declared direct requirements in the captured Linux/CPython context. Raw scanner observations may contain both omissions and extra edges; they need not be a subgraph of the installed reference. Reconstruction outputs remain candidate declarations. Runtime calls, deployed-artifact attestation, and exploitability are unmeasured.

The descriptive question is whether agents add value over the strongest deterministic control with identical permitted observations, context, evidence catalog, and acquisition budgets. This evaluation-only audit does not change the frozen study, its model, calibration, evidence permissions, predictions, or scores.

## Theoretical Background & Sourcing

[Yu, Song, Hu and Yin, 2024, On the Correctness of Metadata-Based SBOM Generation, IEEE/IFIP DSN](https://cs.ucr.edu/~heng/pubs/sbom-dsn24.pdf) investigates generator discrepancies and parser limitations. [Moriwaki et al., 2026, sbom-unifier, ICSME Tool Demonstrations](https://arxiv.org/abs/2608.30708) evaluates field integration/completeness; field presence is kept separate from direct-edge correctness here. [PyPA dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/) define conditional markers and extras. [SPDX 2.3 relationship semantics](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/) define relationship directions. [OpenVEX](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) supplies product/vulnerability status semantics, which package paths alone cannot establish.

## Hypothesis & Experimental Design

All seven methods are compared within the same sealed case. Before any error attribution, prediction digests, the frozen prediction source, model selection without test labels, input/evidence bindings, captured context, reference provenance, saved evaluations, and recorded F1 values are checked. Saved evaluations are recomputed from sealed native predictions against the independent installed reference. Terminal model errors retain their scored outcomes; successful-only means are not used as evidence of superiority.

The frozen raw allocation has 60 projects, two conditions, budget 64 and three repetitions. Repetitions are averaged within project before 10,000 project bootstrap/randomization draws; Holm correction covers all exported contrasts. `completed-project-metrics.csv` separately requires all three repetitions for a project/condition. These estimates concern the selected project population; shared dependencies limit independence. Any subsequent tuned policy requires a new experiment and untouched test projects.

Category C attribution uses only the permitted, content-bound target METADATA catalog and declared context. Known and possible requested extras are propagated from that context through eligible declarations without reading oracle extras. Every matching requirement must evaluate false even with possible transitive activation, and the catalog must parse completely; unknown marker variables remain unresolved. This establishes an artifact/context discrepancy, not a proven internal cause inside the scanner. Per-edge provenance is in `edge-errors.csv` and the snapshot's `allowed-metadata-audit.json` files.

## Empirical Evidence & Downstream Metrics

| Condition | Method | Arms | Edge precision | Edge recall | Whole-edge F1 | New-edge F1 | F1-eligible projects | Non-COMPLETE |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
{table}

In the one-repetition fixed-evidence panel over {panel['projects']} projects, deterministic repair has **{panel['FP']} FP and {panel['FN']} FN direct edges**. **{panel['inherited_FP']} FP edges are already present in the observation.** Context taxonomy: {json.dumps(panel['categories'], sort_keys=True)}. These are project/edge errors in this panel, not independent new projects. Repetition-inclusive counts are explicitly labeled as arm/edge occurrences.

The frozen repair contract supports field setting, component addition and dependency addition. It has no dependency-removal operation (`sbom_recovery/contracts.py`, `RepairProposal`). Consequently, inherited incorrect relationships can remain even when target metadata supports all reference dependencies. This audit does not remove them or substitute corrected predictions. The observed discrepancy points to a separate future reconciliation experiment; it does not establish the performance of that unexecuted method.

`additive-bound.csv` computes an evaluation-only oracle ceiling under preservation of existing edge identities: F1 <= 2|E_reference| / (2|E_reference| + inherited_known_FP). Recovering every missing known reference edge attains that ceiling if no additional FP is introduced. Unknown labels remain excluded. This is a bound for the declared edge-preserving/add-only assumption, not a model prediction or an unrestricted algorithmic upper bound. Fixed-condition counts: {json.dumps(result['fixed_additive_bound'], sort_keys=True)}.

Single-agent arms contain {model_errors}/{single_n} MODEL_ERROR outcomes. `execution-summary.json` separates timeout, connection, response-format, truncation and other recorded error classes; these are observed failure symptoms rather than proof of intrinsic model limitations. Reported tokens, unknown usage and episode durations remain separate. Monetary cost is unmeasured without verified provider pricing.

Retrospective OSV Level 1 assessment uses the original frozen snapshot after sealing. VRR-eligible projects: {len(eligible)}/{result['projects']} ({', '.join(eligible) or 'none'}). `security-summary.json` records newly recovered project/package/advisory triples; advisory aliases are not unique CVEs. Zero denominators remain undefined. VEX triage delta, false-assurance reduction, static call reachability and exploitability are UNMEASURED. Missing paths remain UNKNOWN.

`risk-coverage.json` reports edge-proposal coverage versus selective risk for evidence-gate ranks, with unknown labels disclosed. These ranks are not calibrated model probabilities. Historical studies may include a conformal artifact with unverified temporal exchangeability; current studies omit it. This audit makes no nominal coverage guarantee.

## Failure Taxonomy & Threats to Validity

A namespace/PURL, B dynamic installation, C extras/markers, D registry ambiguity and E sparsity retain their contract meanings. Only evidence-supported C mismatches are assigned automatically; all other causes stay UNRESOLVED. Execution errors and native validation failures have separate units and are not relabeled as graph-causality categories. Accepted changes and blocked unsupported attempts are distinct.

Construct validity: declared package dependencies, field presence, vulnerability visibility and exploitability are different outcomes. Internal validity: references and evidence share underlying package declarations and parsing libraries; target metadata may already be information-sufficient. Contemporary acquisition is retrospective, raw observations contain FP edges, and interim completion times can censor repetitions. External validity: selected pure-Python roots, size/build exclusions, one environment, shared dependencies and unknown model revisions/pretraining constrain generalization. Full controlled and budget-sensitivity completion is a separate milestone from raw-track completion.

## Actionable Next Steps

1. Complete the frozen raw matrix and regenerate this audit with `--require-complete`; preserve all terminal failures.
2. Use the development partition to diagnose operational failures. Any transport or policy revision receives a separate version, with fresh calibration and untouched test projects for a new claim.
3. Preregister evidence-guided edge reconciliation, including explicit preservation of raw observations, justified conflict statuses, and abstention when extras/context or metadata are incomplete. Evaluate the strongest deterministic reconciliation control before attributing gains to an LLM.
4. Preregister the incomplete/conflicting-evidence acquisition study and a separate security-focused cohort described in `research/NEXT_EXPERIMENT.md`. They are planned, not executed results.

Reproduce from the project root: `.venv/bin/python -B scripts/audit_raw_sbom_study.py --study runs/m25-agent-study-v2 --out runs/raw-audit-new`. Add `--wait --require-complete` to wait for the exact frozen raw matrix. Every export uses a fresh output directory and makes zero gateway calls. `provenance.json`, `snapshot-manifest.json`, `report-manifest.json` and `source_bundle/` bind the inputs, predictions, references, evidence and analysis source.
"""
    save_bytes(out / "report/REPORT.md", text.encode())


def plots(out, metrics, edges, execution, risks, result):
    os.environ.setdefault("MPLCONFIGDIR", str(out / ".cache/matplotlib"))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    checkpoint_label = f"{result['status']} — {result['paired_cases']}/{result['expected_cases']} paired raw cases"
    for ax, condition in zip(axes, ("fixed", "active")):
        items = [r for r in metrics if r["condition"] == condition]
        ax.barh([r["method"] for r in items], [r["whole_direct_edge_f1"] or 0 for r in items], color="#256b91")
        ax.set(xlim=(0, 1), xlabel="Project-macro direct-edge F1", title=condition)
    fig.suptitle(checkpoint_label)
    fig.tight_layout()
    for suffix in ("svg", "pdf", "png"):
        fig.savefig(out / f"report/direct-edge-f1.{suffix}")
    plt.close(fig)
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    for ax, condition in zip(axes, ("fixed", "active")):
        items = [r for r in execution if r["condition"] == condition]
        labels = [r["method"] for r in items]
        totals = [r["arms"] for r in items]
        completed = [r["status_counts"].get("COMPLETE", 0) / n for r, n in zip(items, totals)]
        ax.barh(labels, completed, color="#287e60")
        ax.barh(labels, [1-x for x in completed], left=completed, color="#b85844")
        ax.set(xlim=(0, 1), xlabel="Fraction of recorded arms (green COMPLETE)", title=condition)
    fig.suptitle(checkpoint_label)
    fig.tight_layout()
    for suffix in ("svg", "pdf", "png"):
        fig.savefig(out / f"report/execution-status.{suffix}")
    plt.close(fig)
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    for ax, condition in zip(axes, ("fixed", "active")):
        items = [r for r in edges if r["condition"] == condition]
        methods = sorted({r["method"] for r in items})
        inherited, introduced, missed = [], [], []
        for method in methods:
            fp = next((r for r in items if r["method"] == method and r["direction"] == "FP"), {})
            fn = next((r for r in items if r["method"] == method and r["direction"] == "FN"), {})
            inherited.append(fp.get("origin_counts", {}).get("INHERITED_FROM_OBSERVATION", 0))
            introduced.append(fp.get("origin_counts", {}).get("INTRODUCED_BY_METHOD", 0))
            missed.append(fn.get("error_occurrences", 0))
        ax.barh(methods, inherited, label="Inherited FP", color="#bc674b")
        ax.barh(methods, introduced, left=inherited, label="New FP", color="#783f69")
        ax.barh(methods, missed, left=[a+b for a, b in zip(inherited, introduced)], label="FN", color="#446d99")
        ax.set(xlabel="Arm/edge error occurrences (includes repetitions)", title=condition)
        ax.legend(fontsize=8)
    fig.suptitle(checkpoint_label)
    fig.tight_layout()
    for suffix in ("svg", "pdf", "png"):
        fig.savefig(out / f"report/edge-error-origins.{suffix}")
    plt.close(fig)
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    for ax, condition in zip(axes, ("fixed", "active")):
        for group in risks:
            if group["condition"] != condition or not group["curve"]:
                continue
            ax.plot([r["coverage"] for r in group["curve"]],
                    [r["selective_risk"] for r in group["curve"]], marker="o", label=group["method"])
        ax.set(xlim=(0, 1.02), ylim=(-.02, 1.02), xlabel="Coverage of known edge-proposal labels",
               ylabel="Selective risk", title=condition + " — evidence-gate ranks")
        if ax.lines:
            ax.legend(fontsize=8)
    fig.suptitle(checkpoint_label + "\nEdge proposals; unknown labels excluded and counted in risk-coverage.json")
    fig.tight_layout()
    for suffix in ("svg", "pdf", "png"):
        fig.savefig(out / f"report/risk-coverage.{suffix}")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", default="runs/m25-agent-study-v2")
    parser.add_argument("--out", required=True)
    parser.add_argument("--wait", action="store_true", help="Wait without inference until the full raw matrix is scored")
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=30.)
    args = parser.parse_args()
    if not 1 <= args.poll_seconds <= 60:
        parser.error("poll-seconds must be between 1 and 60")
    study, out = Path(args.study).resolve(), Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    # Lock lives outside the fresh output; an interrupted export is preserved.
    lock_path = out.with_name(out.name + ".lock")
    with lock_path.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if out.exists():
            raise ValueError("Audit output already exists; choose a fresh directory")
        try:
            if args.wait:
                while True:
                    progress, _, _ = matrix_progress(study)
                    save(out.with_name(out.name + ".job.json"), {"updated_at": now(), "status": "READY" if progress["complete"] else "WAITING_RAW",
                        "study": str(study), "out": str(out), "llm_api_calls": 0, **progress})
                    print(json.dumps({"raw_progress": progress}), flush=True)
                    if progress["complete"]:
                        break
                    time.sleep(args.poll_seconds)
            result = export(study, out, require_complete=args.require_complete or args.wait)
        except BaseException as exc:
            save(out.with_name(out.name + ".job.json"), {"status": "FAILED", "updated_at": now(),
                "exception_type": type(exc).__name__, "partial_outputs_preserved": out.exists(), "llm_api_calls": 0})
            raise
        save(out.with_name(out.name + ".job.json"), {"status": "EXPORTED", "updated_at": now(), "result": result})
        print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
