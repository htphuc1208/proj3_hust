"""Run Experiment E1 (Same Evidence, Different Decision) on the 9 Pilot Projects.

Compares:
- B0: Priority (Replicates sbom-unifier fixed-priority merging)
- B1: Majority (Independent source vote)
- B2: Field-Aware Rules (Provenance authority, scope filtering, calibrated abstention)
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from sbom_recovery.canonical import CanonicalLedger
from sbom_recovery.e1_experiment import E1DecisionEngine
from sbom_recovery.agent_adjudicator import AgentAdjudicator
from sbom_recovery.live_agent_adjudicator import LiveAgentAdjudicator


def main():
    ledgers_dir = Path("runs/pilot-audit-v1/ledgers")
    out_dir = Path("runs/e1-pilot-v1")
    out_dir.mkdir(parents=True, exist_ok=True)

    b0_dir = out_dir / "b0_priority"
    b1_dir = out_dir / "b1_majority"
    b2_dir = out_dir / "b2_field_aware"
    a1_dir = out_dir / "a1_agent"
    a1_live_dir = out_dir / "a1_live_agent"
    for d in (b0_dir, b1_dir, b2_dir, a1_dir, a1_live_dir):
        d.mkdir(parents=True, exist_ok=True)

    ledger_files = sorted(ledgers_dir.glob("*.json"))
    if not ledger_files:
        raise FileNotFoundError(f"No ledgers found in {ledgers_dir}. Run scripts/run_pilot_audit.py first.")

    e1_results = []

    print("=" * 110)
    print("EXPERIMENT E1: SAME EVIDENCE, DIFFERENT DECISION (B0 vs B1 vs B2 vs A1)")
    print("=" * 110)
    h_case = "Case ID"
    h_total = "Decisions"
    h_conf = "Conflicts"
    h_b0_edges = "B0 Edges"
    h_b2_edges = "B2 Edges"
    h_a1_edges = "A1 Edges"
    h_a1_abst = "A1 Abstain"
    h_delta = "Delta(A1!=B0)"
    print(f"{h_case:35} | {h_total:9} | {h_conf:9} | {h_b0_edges:9} | {h_b2_edges:9} | {h_a1_edges:9} | {h_a1_abst:10} | {h_delta:12}")
    print("-" * 110)

    live_adj = LiveAgentAdjudicator(api_key=os.environ.get("NETMIND_API_KEY"))

    for lpath in ledger_files:
        case_id = lpath.stem
        ledger = CanonicalLedger.load(lpath)

        res_b0 = E1DecisionEngine.resolve_b0_priority(ledger)
        res_b1 = E1DecisionEngine.resolve_b1_majority(ledger)
        res_b2 = E1DecisionEngine.resolve_b2_field_aware(ledger)
        res_a1_ledger = AgentAdjudicator.resolve_ledger(ledger)
        res_a1_live_ledger = live_adj.resolve_ledger_live(ledger)

        # Save resolved ledgers
        res_b0.resolved_ledger.save(b0_dir / f"{case_id}.json")
        res_b1.resolved_ledger.save(b1_dir / f"{case_id}.json")
        res_b2.resolved_ledger.save(b2_dir / f"{case_id}.json")
        res_a1_ledger.save(a1_dir / f"{case_id}.json")
        res_a1_live_ledger.save(a1_live_dir / f"{case_id}.json")

        b0_claims = {(c.subject, c.predicate): str(c.object) for c in res_b0.resolved_ledger.claims}
        a1_claims = {(c.subject, c.predicate): str(c.object) for c in res_a1_ledger.claims}
        a1_live_claims = {(c.subject, c.predicate): str(c.object) for c in res_a1_live_ledger.claims}

        b0_edges = len(res_b0.resolved_ledger.get_claims(predicate="depends_on"))
        b2_edges = len(res_b2.resolved_ledger.get_claims(predicate="depends_on"))
        a1_edges = len(res_a1_ledger.get_claims(predicate="depends_on"))
        a1_live_edges = len(res_a1_live_ledger.get_claims(predicate="depends_on"))
        a1_abst = len([c for c in res_a1_ledger.claims if c.status == "unknown"])
        a1_live_abst = len([c for c in res_a1_live_ledger.claims if c.status == "unknown"])

        disagreements = 0
        common_keys = set(b0_claims) & set(a1_live_claims)
        for k in common_keys:
            if k[1] != "depends_on" and b0_claims[k] != a1_live_claims[k]:
                disagreements += 1

        print(
            f"{case_id:35} | {res_b0.total_decisions:9} | {res_b0.conflict_decisions:9} | "
            f"{b0_edges:9} | {b2_edges:9} | {a1_live_edges:9} | {a1_live_abst:10} | {disagreements:12}"
        )

        e1_results.append({
            "case_id": case_id,
            "total_decisions": res_b0.total_decisions,
            "conflict_decisions": res_b0.conflict_decisions,
            "b0_priority": {
                "edges": b0_edges,
                "claims": len(res_b0.resolved_ledger.claims),
                "abstentions": res_b0.abstentions,
            },
            "b1_majority": {
                "edges": len(res_b1.resolved_ledger.get_claims(predicate="depends_on")),
                "claims": len(res_b1.resolved_ledger.claims),
                "abstentions": res_b1.abstentions,
            },
            "b2_field_aware": {
                "edges": b2_edges,
                "claims": len(res_b2.resolved_ledger.claims),
                "abstentions": res_b2.abstentions,
            },
            "a1_agent_deterministic": {
                "edges": a1_edges,
                "claims": len(res_a1_ledger.claims),
                "abstentions": a1_abst,
            },
            "a1_agent_live_llm": {
                "edges": a1_live_edges,
                "claims": len(res_a1_live_ledger.claims),
                "abstentions": a1_live_abst,
                "disagreements_with_b0": disagreements,
            },
        })

    live_adj.close()

    report_path = out_dir / "e1_pilot_summary.json"
    report_path.write_text(json.dumps(e1_results, indent=2, sort_keys=True), encoding="utf-8")
    print("=" * 110)
    print(f"E1 Summary Report saved to {report_path}")


if __name__ == "__main__":
    main()
