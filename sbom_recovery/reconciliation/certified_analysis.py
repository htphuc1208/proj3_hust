"""Evaluation after seals; uncertainty is never silently converted to a negative."""
from collections import Counter
import json
from pathlib import Path

from sbom_recovery.core.formats import NativeDocument, package_purl, sha
from sbom_recovery.metrics.metrics import evaluate, graph_facts, paired_bootstrap, holm
from .certified_worker import METHODS


def load(path):
    return json.loads(Path(path).read_text())


def verify_matrix(job, output):
    job, output = Path(job), Path(output)
    matrix = load(output / "matrix-seal.json")
    document, context, manifest = (load(job / p) for p in ("observation.json", "context.json", "evidence/manifest.json"))
    if set(matrix["arms"]) != set(METHODS) or matrix["job_sha256"] != sha(load(job / "job.json")):
        raise ValueError("Unexpected prediction allocation/job")
    result = {}
    for method in METHODS:
        directory = output / method
        prediction, details, seal = (load(directory / p) for p in ("prediction.json", "details.json", "seal.json"))
        if (sha(seal) != matrix["arms"][method] or seal["prediction_sha256"] != sha(prediction)
                or seal["details_sha256"] != sha(details) or seal["input_sha256"] != sha(document)
                or seal["context_sha256"] != sha(context) or seal["evidence_sha256"] != sha(manifest)):
            raise ValueError("Prediction, evidence, context or seal changed")
        result[method] = prediction, details
    return result


def score_changes(observation, prediction, reference, unresolved_parents=()):
    native = NativeDocument(observation)
    identities = {r: package_purl(p, native.format) for r, p in native.packages().items()}
    counts = Counter(identities.values())
    truth_nodes, truth_edges = graph_facts(reference)
    before, after = native.edges(), NativeDocument(prediction).edges()
    records = []
    for operation, changes in (("add", after - before), ("retract", before - after)):
        for source, target in sorted(changes):
            parent, child = identities.get(source), identities.get(target)
            correct = None
            # Old references are coordinate-level. Multiple occurrences cannot
            # acquire an instance label merely because they share that PURL.
            if (parent and child and counts[parent] == counts[child] == 1
                    and parent in truth_nodes and child in truth_nodes):
                if (parent, child) in truth_edges:
                    correct = operation == "add"
                elif parent not in unresolved_parents:
                    correct = operation == "retract"
            records.append({"source_ref": source, "target_ref": target, "operation": operation,
                            "correct": correct, "reference_scope": "COORDINATE_LEVEL_UNAMBIGUOUS_ENDPOINTS"})
    known = [r for r in records if r["correct"] is not None]
    errors = sum(r["correct"] is False for r in known)
    unknown = len(records) - len(known)
    return {"records": records, "known_changes": len(known), "incorrect_changes": errors,
            "unknown_changes": unknown, "selective_risk": errors / len(known) if known else None,
            "optimistic_risk": errors / len(records) if records else None,
            "pessimistic_risk": (errors + unknown) / len(records) if records else None}


def score_arm(observation, prediction, details, reference, unresolved_parents):
    evaluation = evaluate(reference, observation, prediction, unresolved_parents=unresolved_parents)
    changes = score_changes(observation, prediction, reference, unresolved_parents)
    observed_edges = NativeDocument(observation).edges()
    decisions = details.get("decisions", [])
    decided = sum((d["source_ref"], d["target_ref"]) in observed_edges
                  and d["status"] in {"SUPPORTED", "REFUTED"} for d in decisions)
    return {"status": details["status"], "native_valid": details["validation"]["valid"],
            "whole_edges": evaluation["whole_edges"], "unknown_label_edges": evaluation["unknown_label_edge_count"],
            "changes": changes, "seconds": details["seconds"],
            "decision_coverage": decided / len(observed_edges) if decisions and observed_edges else None,
            "coverage_denominator": "all observed native dependency edges; scope-unknown edges remain undecided",
            "assessment_counts": details.get("counts", {}), "operations": details.get("operations", {})}


def summarize(records, failures):
    methods, stats_rows = {}, []
    for method in METHODS:
        rows = [r["arms"][method] for r in records]
        known = sum(r["changes"]["known_changes"] for r in rows)
        errors = sum(r["changes"]["incorrect_changes"] for r in rows)
        methods[method] = {"scored_cases": len(rows), "status_counts": dict(Counter(r["status"] for r in rows)),
            "known_changes": known, "incorrect_changes": errors,
            "unknown_changes": sum(r["changes"]["unknown_changes"] for r in rows),
            "pooled_selective_risk": errors / known if known else None}
        for metric in ("f1", "precision", "recall"):
            values = [r["whole_edges"][metric] for r in rows if r["whole_edges"][metric] is not None]
            methods[method]["available_case_" + metric] = sum(values) / len(values) if values else None
            methods[method][metric + "_eligible_cases"] = len(values)
        for record, row in zip(records, rows):
            stats_rows.append({"project": record["project"], "condition": record["condition"], "method": method,
                "metrics": {"f1": row["whole_edges"]["f1"], "selective_risk": row["changes"]["selective_risk"],
                            "decision_coverage": row["decision_coverage"]}})
    contrasts = holm([paired_bootstrap(stats_rows, "certified_v2", baseline, metric)
                      for baseline in ("legacy_reconciliation", "metadata_control")
                      for metric in ("f1", "selective_risk", "decision_coverage")])
    equal = sum(r["same_graph_as_metadata_control"] for r in records)
    informative = sum(any(v > 0 for k, v in r["arms"]["certified_v2"].get("assessment_counts", {}).items()
                          if k in {"SUPPORTED", "REFUTED"}) for r in records)
    panels = {}
    for condition in sorted({r["condition"] for r in records}):
        panel = [r for r in records if r["condition"] == condition and r.get("reference_edges", 0) > 0
                 and all(r["arms"][m]["whole_edges"]["f1"] is not None for m in METHODS)]
        all_cases = [r for r in records if r["condition"] == condition]
        panels[condition] = {"common_nonempty_reference_projects": len(panel), "methods": {m: {
            "f1": sum(r["arms"][m]["whole_edges"]["f1"] for r in panel) / len(panel) if panel else None,
            "fp_all_projects": sum(r["arms"][m]["whole_edges"]["fp"] for r in all_cases),
            "fn_all_projects": sum(r["arms"][m]["whole_edges"]["fn"] for r in all_cases)} for m in METHODS}}
    return {"status": "COMPLETE_DEVELOPMENT" if not failures else "PARTIAL_DEVELOPMENT",
            "partition": "development", "projects": len({r["project"] for r in records}), "cases": len(records),
            "failures": failures, "methods": methods, "contrasts": contrasts,
            "same_graph_as_strong_control_cases": equal,
            "cases_with_determinate_v2_assessments": informative, "common_f1_panels": panels,
            "empirical_advantage_gate": ("UNMEASURED_INCOMPLETE_RUN" if failures or not records else
                "UNMEASURED_NO_DETERMINATE_DECISIONS" if not informative else
                "NOT_MET_EQUAL_STRONG_CONTROL" if equal == len(records) else "REQUIRES_CASE_AND_EFFECT_REVIEW"),
            "novelty": "NOT_ESTABLISHED_BY_IMPLEMENTATION_OR_UNIT_TESTS",
            "reference_scope": "Frozen independent installed declarations; coordinate-level scoring, shared metadata/standards limitations",
            "heldout_projects_used": 0, "llm_api_calls": 0, "human_review_completed": 0,
            "records": records}
