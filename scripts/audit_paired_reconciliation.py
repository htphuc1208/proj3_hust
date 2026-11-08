#!/usr/bin/env python3
"""Re-score sealed development outputs; no inference, acquisitions, or policy edits."""
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research_core import digest, load
from sbom_recovery.campaign import score_after_seal
from sbom_recovery.formats import NativeDocument, package_purl, sha, validate_native
from sbom_recovery.metrics import paired_bootstrap
from sbom_recovery.reconciliation_comparison import METHODS, summarize, verify_predictions
from sbom_recovery.storage import save


def audit(run, out):
    run, out = Path(run).resolve(), Path(out)
    out.mkdir(parents=True, exist_ok=False)
    hashes = load(run / "artifact-hashes.json")
    for relative, expected in hashes.items():
        if digest(run / relative) != expected:
            raise ValueError("Frozen artifact changed: " + relative)
    plan, summary = load(run / "plan.json"), load(run / "summary.json")
    if sha(plan) != summary["plan_sha256"] or len(plan["cases"]) != 20:
        raise ValueError("Plan/summary mismatch")
    derived = summarize(summary["records"])
    if any(summary[key] != value for key, value in derived.items()):
        raise ValueError("Summary differs from saved project measurements")
    rows, residual = [], []
    checked, valid = 0, 0
    reasons = Counter()
    for spec in plan["cases"]:
        case, capture = run / spec["project"], Path(spec["capture"])
        observation, context = load(case / "input/observation.json"), load(case / "input/context.json")
        if sha(observation) != spec["input_sha256"] or sha(context) != spec["context_sha256"]:
            raise ValueError("Frozen input/context changed")
        docs, details = verify_predictions(case / "worker/result", observation, context)
        record = next(r for r in summary["records"] if r["project"] == spec["project"])
        for relative, expected in record["reference_hashes"].items():
            if digest(capture / "oracle" / relative) != expected:
                raise ValueError("Reference changed since sealed evaluation")
        for method in METHODS:
            evaluation = score_after_seal(capture, observation, docs[method])
            if evaluation != load(case / method / "evaluation.json"):
                raise ValueError("Independent re-scoring mismatch")
            if (evaluation["whole_edges"] != record["arms"][method]["whole_edges"]
                    or evaluation["new_edges"] != record["arms"][method]["new_edges"]):
                raise ValueError("Recorded project score mismatch")
            native_valid = validate_native(docs[method])["valid"]
            if native_valid != record["arms"][method]["native_valid"]:
                raise ValueError("Native validation mismatch")
            checked += 1
            valid += native_valid
            if record["reference_edges"] > 0:
                rows.append({"project": spec["project"], "method": method,
                             "metrics": evaluation["whole_edges"]})
        combined = docs["additive_reconciliation"]
        native = NativeDocument(combined)
        purls = {ref: package_purl(p, native.format) for ref, p in native.packages().items()}
        assessment = details["additive_reconciliation"].get("assessment", {})
        for edge in load(case / "additive_reconciliation/evaluation.json")["false_positive_edges"]:
            matches = [r for r in assessment.get("assessments", [])
                       if [purls.get(r["source_ref"]), purls.get(r["target_ref"])] == edge]
            explanation = sorted({r["reason"] for r in matches})
            reasons.update(explanation or ["NO_MATCHING_ASSESSMENT"])
            residual.append({"project": spec["project"], "edge": edge, "failure_category": "UNRESOLVED",
                             "assessment_reasons": explanation,
                             "snapshot_diagnostics": assessment.get("diagnostics", []),
                             "interpretation": "Abstention reasons are not a proven scanner-internal causal attribution"})
    intervals = []
    for method, baseline in (("additive", "observed"), ("additive_reconciliation", "additive"),
                             ("additive_reconciliation", "observed")):
        for metric in ("precision", "recall", "f1"):
            value = paired_bootstrap(rows, method, baseline, metric, repetitions=10000, seed=42)
            # Export descriptive intervals only; no significance test/familywise guarantee.
            intervals.append({k: v for k, v in value.items() if k != "p_value"})
    result = {"status": "PASSED", "checked_arms": checked, "native_valid_arms": valid,
              "projects": len(plan["cases"]), "frozen_artifacts_checked": len(hashes),
              "summary_recomputed": True, "prediction_seals_checked": True,
              "residual_known_fp": len(residual), "residual_assessment_reasons": dict(reasons),
              "failure_taxonomy": {"A": 0, "B": 0, "C": 0, "D": 0, "E": 0, "UNRESOLVED": len(residual)},
              "independence": "Separate re-scoring execution; shared evaluator/standards libraries, not human QA",
              "interval_scope": "Exploratory pointwise project-bootstrap intervals on the common 11-project nonempty-reference panel; selected development population/shared dependencies limit interpretation; no familywise or generalization guarantee",
              "project_intervals": intervals, "llm_api_calls": 0,
              "source_hashes": {"audit": digest(__file__), "comparison": digest(ROOT / "sbom_recovery/reconciliation_comparison.py"),
                                "metrics": digest(ROOT / "sbom_recovery/metrics.py")},
              "run_manifest_sha256": digest(run / "artifact-hashes.json")}
    save(out / "verification.json", result)
    save(out / "residual-edges.json", residual)
    print({k: result[k] for k in ("status", "checked_arms", "native_valid_arms", "residual_known_fp", "residual_assessment_reasons")})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    audit(args.run, args.out)


if __name__ == "__main__":
    main()
