"""Benchmark script to score B0, B1, B2 across pilot cases against Gold.

Outputs the primary comparative metrics table:
- Precision, Recall, F1
- Verified Recovery Rate (VRR)
- False Assertion Rate (FAR)
- Conflict Resolution Accuracy
- Abstention Rate (uncalibrated)
"""
from __future__ import annotations

import json
from pathlib import Path
from sbom_recovery.canonical import CanonicalLedger
from sbom_recovery.claim_scorer import ClaimScorer
from sbom_recovery.gold_builder import GoldBuilder


def main():
    e1_dir = Path("runs/e1-pilot-v1")
    input_dir = Path("runs/pilot-audit-v1/ledgers")
    gold_dir = Path("runs/pilot-audit-v1/gold")
    gold_dir.mkdir(parents=True, exist_ok=True)
    out_dir = Path("runs/e1-benchmark-v1")
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Build Gold for requests from installed reference
    requests_gold = GoldBuilder.build_gold(
        case_id="pilot-python-requests",
        ecosystem="pypi",
        manifest_path="research/.work/m25-cohort-captures-v2/requests/source/pyproject.toml",
        resolved_path="research/.work/m25-cohort-captures-v2/requests/oracle/installed_reference.json",
    )
    requests_gold.save(gold_dir / "pilot-python-requests.json")

    # Score requests
    case_id = "pilot-python-requests"
    input_l = CanonicalLedger.load(input_dir / f"{case_id}.json")
    b0_l = CanonicalLedger.load(e1_dir / "b0_priority" / f"{case_id}.json")
    b1_l = CanonicalLedger.load(e1_dir / "b1_majority" / f"{case_id}.json")
    b2_l = CanonicalLedger.load(e1_dir / "b2_field_aware" / f"{case_id}.json")
    a1_l = CanonicalLedger.load(e1_dir / "a1_agent" / f"{case_id}.json")
    a1_live_l = CanonicalLedger.load(e1_dir / "a1_live_agent" / f"{case_id}.json")

    scores = []
    for strat, l in [
        ("B0_Priority (project reimplementation)", b0_l),
        ("B1_Majority", b1_l),
        ("B2_FieldAware", b2_l),
        ("A1_Agent (Deterministic)", a1_l),
        ("A1_Live_LLM (Qwen-3.6)", a1_live_l),
    ]:
        rep = ClaimScorer.evaluate_case(
            case_id=case_id,
            strategy=strat,
            gold_ledger=requests_gold,
            input_ledger=input_l,
            predicted_ledger=l,
        )
        scores.append(rep.model_dump(mode="json"))

    out_file = out_dir / "requests_benchmark_scores.json"
    out_file.write_text(json.dumps(scores, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Saved benchmark scores to {out_file}")

    print("\n" + "=" * 95)
    print(f"PILOT EVALUATION: {case_id} (Ground Truth vs Baselines)")
    print("=" * 95)
    h_strat = "Strategy"
    h_prec = "Precision"
    h_rec = "Recall"
    h_f1 = "F1"
    h_far = "FAR (False Assert)"
    h_vrr = "VRR"
    h_assert = "Asserted"
    print(f"{h_strat:30} | {h_prec:10} | {h_rec:8} | {h_f1:8} | {h_far:18} | {h_vrr:8} | {h_assert:8}")
    print("-" * 95)

    for r in scores:
        strat = r["strategy"]
        ov = r["overall_metrics"]
        p_str = f"{ov['precision']:.4f}" if ov["precision"] is not None else "N/A"
        r_str = f"{ov['recall']:.4f}" if ov["recall"] is not None else "N/A"
        f_str = f"{ov['f1']:.4f}" if ov["f1"] is not None else "N/A"
        far_str = f"{r['far']:.4f}" if r["far"] is not None else "N/A"
        vrr_str = f"{r['vrr']:.4f}" if r["vrr"] is not None else "N/A"
        print(f"{strat:30} | {p_str:10} | {r_str:8} | {f_str:8} | {far_str:18} | {vrr_str:8} | {r['total_asserted']:8}")
    print("=" * 95)


if __name__ == "__main__":
    main()
