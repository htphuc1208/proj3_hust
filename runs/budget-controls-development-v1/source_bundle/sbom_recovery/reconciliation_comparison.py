"""Evaluation-only integrity checks and stage attribution for the three-arm study."""
from __future__ import annotations

from collections import Counter
import hashlib
from pathlib import Path
import statistics

from research_core import load
from .formats import NativeDocument, sha
from .metrics import graph_facts

METHODS = ("observed", "additive", "additive_reconciliation")


def verify_predictions(directory, observation, context):
    root = Path(directory)
    matrix = load(root / "matrix-seal.json")
    manifest, contract = load(root / "evidence-manifest.json"), load(root / "evidence-contract.json")
    if (matrix["methods"] != list(METHODS) or set(matrix["arms"]) != set(METHODS)
            or matrix["input_sha256"] != sha(observation) or matrix["context_sha256"] != sha(context)
            or matrix["target_id"] != context["target_id"] or matrix["reference_labels_read"] is not False
            or matrix["evidence_manifest_sha256"] != sha(manifest)
            or matrix["evidence_contract_sha256"] != sha(contract)):
        raise ValueError("Matrix/input/context/evidence seal mismatch")
    if (contract["evidence_manifest_sha256"] != sha(manifest)
            or contract["context_sha256"] != sha(context) or contract["target_id"] != context["target_id"]):
        raise ValueError("Evidence contract mismatch")
    expected = {"target:" + row["path"]: row["sha256"] for row in contract["sources"]}
    found = {}
    for record in manifest["records"]:
        identity = {k: v for k, v in record.items() if k not in {"acquired_at", "evidence_id"}}
        if (sha(identity) != record["evidence_id"] or record["kind"] != "target_metadata"
                or record["target_id"] != context["target_id"] or record["authority"] != "VERIFIED_TARGET"
                or record["available_at"] != contract["available_at"] or record["source"] in found):
            raise ValueError("Evidence identity/authority mismatch")
        if hashlib.sha256((root / "evidence/blobs" / record["sha256"]).read_bytes()).hexdigest() != record["sha256"]:
            raise ValueError("Evidence blob changed")
        found[record["source"]] = record["sha256"]
    if found != expected:
        raise ValueError("Methods do not share the complete bound source set")
    predictions, details = {}, {}
    for method in METHODS:
        prediction = load(root / method / "prediction.json")
        detail = load(root / method / "details.json")
        seal = load(root / method / "seal.json")
        if (matrix["arms"][method] != sha(seal) or seal["method"] != method
                or seal["prediction_sha256"] != sha(prediction) or seal["details_sha256"] != sha(detail)
                or seal["input_sha256"] != sha(observation) or seal["context_sha256"] != sha(context)
                or seal["evidence_manifest_sha256"] != sha(manifest) or seal["reference_labels_read"] is not False
                or detail["input_sha256"] != sha(observation) or detail["context_sha256"] != sha(context)
                or detail["evidence_manifest_sha256"] != sha(manifest)):
            raise ValueError("Arm seal or paired evidence mismatch: " + method)
        predictions[method], details[method] = prediction, detail
    if sha(predictions["observed"]) != sha(observation):
        raise ValueError("Observed arm changed the input")
    if not NativeDocument(observation).edges() <= NativeDocument(predictions["additive"]).edges():
        raise ValueError("Existing additive policy removed native edges")
    combined = details["additive_reconciliation"]
    if "assessment" in combined:
        assessment = combined["assessment"]
        if (combined["additive_prediction_sha256"] != sha(predictions["additive"])
                or assessment["input_sha256"] != sha(predictions["additive"])
                or assessment["output_sha256"] != sha(predictions["additive_reconciliation"])):
            raise ValueError("Reconciliation did not consume the paired additive prediction")
        left, right = (NativeDocument(predictions[m]).edges() for m in ("additive", "additive_reconciliation"))
        if right - left or left - right != set(map(tuple, assessment["retracted_edges"])):
            raise ValueError("Retraction sidecar differs from derived native edges")
    return predictions, details


def stage_changes(before, after, reference, unresolved_parents=()):
    """Facts are PURL pairs, distinct from native-reference edge operations."""
    left, right, truth = (graph_facts(d)[1] for d in (before, after, reference))
    def label(edge):
        return "KNOWN_TRUE" if edge in truth else "UNKNOWN" if edge[0] in unresolved_parents else "KNOWN_FALSE"
    return {direction: [{"edge": list(edge), "label": label(edge)} for edge in sorted(edges)]
            for direction, edges in (("added", right - left), ("removed", left - right))}


def paired_metrics(records, nonempty_reference=False):
    """One denominator per metric shared by all arms; never fill undefined with 1."""
    population = [r for r in records if "arms" in r and (not nonempty_reference or r["reference_edges"] > 0)]
    result = {"population_projects": len(population), "metrics": {}}
    for metric in ("precision", "recall", "f1"):
        eligible = [r for r in population if all(r["arms"][m]["whole_edges"][metric] is not None for m in METHODS)]
        result["metrics"][metric] = {"eligible_projects": len(eligible), "means": {
            m: statistics.mean(r["arms"][m]["whole_edges"][metric] for r in eligible) if eligible else None
            for m in METHODS}}
    return result


def summarize(records):
    scored = [r for r in records if "arms" in r]
    totals = {}
    for method in METHODS:
        arms = [r["arms"][method] for r in scored]
        totals[method] = {
            "projects": len(arms), "status_counts": dict(Counter(a["status"] for a in arms)),
            "native_invalid": sum(not a["native_valid"] for a in arms),
            "edge_counts": {k: sum(a["whole_edges"][k] for a in arms) for k in ("tp", "fp", "fn")},
            "new_edges": {k: sum(a["new_edges"][k] for a in arms) for k in ("tp", "fp", "fn")},
            "unknown_label_edges": sum(a["unknown_label_edges"] for a in arms),
            "mean_policy_seconds": statistics.mean(a["duration_seconds"] for a in arms) if arms else None,
            "available_case_means": {metric: {
                "eligible_projects": sum(a["whole_edges"][metric] is not None for a in arms),
                "mean": statistics.mean(a["whole_edges"][metric] for a in arms if a["whole_edges"][metric] is not None)
                        if any(a["whole_edges"][metric] is not None for a in arms) else None}
                for metric in ("precision", "recall", "f1")}}
    changes = {}
    for stage in ("additive", "reconciliation"):
        changes[stage] = {direction: dict(Counter(row["label"] for r in scored
            for row in r["stage_changes"][stage][direction])) for direction in ("added", "removed")}
    assessments = Counter()
    for record in scored:
        assessments.update(record["arms"]["additive_reconciliation"]["assessment_counts"])
    removed = changes["reconciliation"]["removed"]
    known = removed.get("KNOWN_TRUE", 0) + removed.get("KNOWN_FALSE", 0)
    total_assessed = sum(assessments.values())
    return {"scored_projects": len(scored), "totals": totals, "stage_changes": changes,
            "paired_all_projects": paired_metrics(records),
            "paired_nonempty_reference": paired_metrics(records, True),
            "empty_reference_projects": sum(r["reference_edges"] == 0 for r in scored),
            "assessment_counts": dict(assessments),
            "retraction_operating_point": {
                "population": "Native direct edges in additive predictions, across projects",
                "assessed_edges": total_assessed,
                "coverage": assessments["CONTRADICTED"] / total_assessed if total_assessed else None,
                "known_labeled_retractions": known, "unknown_labeled_retractions": removed.get("UNKNOWN", 0),
                "selective_risk": removed.get("KNOWN_TRUE", 0) / known if known else None,
                "calibration": "UNMEASURED; one deterministic operating point, no probability threshold"},
            "identity_changed_refs": sum(len(r["arms"]["additive"]["native_changes"]["changed_identity_refs"]) for r in scored),
            "native_edge_additions": sum(len(r["arms"]["additive"]["native_changes"]["added_native_edges"]) for r in scored),
            "native_edge_retractions": sum(len(r["arms"]["additive_reconciliation"]["native_changes_from_additive"]["removed_native_edges"]) for r in scored)}
