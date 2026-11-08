"""Experiment E2: Same Tool Budget, Different Evidence Acquisition.

Compares evidence acquisition efficiency across budgets K in [0, 2, 5, 10, 20]:
- D1: Fixed-Order (lockfiles -> manifests)
- D2: Deterministic Greedy (heuristic information-gain ranking)
- A2: Dynamic Agent Planner (root-first, conflict-directed, early-stopping)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sbom_recovery.canonical import CanonicalLedger
from sbom_recovery.acquisition_tools import (
    AgentPlanner,
    BudgetedScheduler,
    DeterministicSchedulers,
    EvidenceToolCatalog,
)


BUDGETS = [0, 2, 5, 10, 20]


def main():
    captures_dir = Path("research/.work/m25-cohort-captures-v2")
    ledgers_dir = Path("runs/pilot-audit-v1/ledgers")
    out_dir = Path("runs/e2-pilot-v1")
    out_dir.mkdir(parents=True, exist_ok=True)

    pilot_cases = [
        ("pilot-python-requests", "requests"),
        ("pilot-python-flask", "flask"),
        ("pilot-python-rich", "rich"),
    ]

    e2_results = []

    print("=" * 110)
    print("EXPERIMENT E2: SAME TOOL BUDGET, DIFFERENT EVIDENCE ACQUISITION (D1 vs D2 vs A2)")
    print("=" * 110)
    h_case = "Case ID"
    h_b = "Budget"
    h_d1_act = "D1 Act"
    h_d1_bytes = "D1 Bytes"
    h_d2_act = "D2 Act"
    h_d2_bytes = "D2 Bytes"
    h_a2_act = "A2 Act"
    h_a2_bytes = "A2 Bytes"
    print(f"{h_case:25} | {h_b:6} | {h_d1_act:8} | {h_d1_bytes:10} | {h_d2_act:8} | {h_d2_bytes:10} | {h_a2_act:8} | {h_a2_bytes:10}")
    print("-" * 110)

    for case_id, proj_name in pilot_cases:
        proj_dir = captures_dir / proj_name
        lpath = ledgers_dir / f"{case_id}.json"
        if not lpath.exists():
            continue

        ledger = CanonicalLedger.load(lpath)
        conflicts = list(ledger.find_conflicts().keys())

        # Collect available candidate files
        available_files = []
        if proj_dir.exists():
            for f in proj_dir.rglob("*"):
                if f.is_file():
                    rel = str(f.relative_to(proj_dir))
                    available_files.append(rel)
        if not available_files:
            # Fallback mock sandbox for evaluation
            available_files = ["source/pyproject.toml", "source/uv.lock", "oracle/installed_reference.json"]

        manifest_files = [f for f in available_files if "pyproject.toml" in f or "manifest" in f]
        lockfiles = [f for f in available_files if "lock" in f or "reference" in f]

        for budget in BUDGETS:
            catalog = EvidenceToolCatalog(target_dir=proj_dir)

            # 1. Run D1
            sched_d1 = BudgetedScheduler(catalog=catalog, max_actions=budget)
            DeterministicSchedulers.run_d1_fixed_order(sched_d1, manifest_files, lockfiles)

            # 2. Run D2
            sched_d2 = BudgetedScheduler(catalog=catalog, max_actions=budget)
            DeterministicSchedulers.run_d2_greedy(sched_d2, conflicts, available_files)

            # 3. Run A2
            sched_a2 = BudgetedScheduler(catalog=catalog, max_actions=budget)
            AgentPlanner.run_a2_planner(sched_a2, conflicts, available_files)

            print(
                f"{case_id:25} | {budget:6} | "
                f"{sched_d1.actions_used:8} | {sched_d1.bytes_used:10} | "
                f"{sched_d2.actions_used:8} | {sched_d2.bytes_used:10} | "
                f"{sched_a2.actions_used:8} | {sched_a2.bytes_used:10}"
            )

            e2_results.append({
                "case_id": case_id,
                "budget": budget,
                "d1_fixed_order": {
                    "actions_used": sched_d1.actions_used,
                    "bytes_used": sched_d1.bytes_used,
                    "history": [h.model_dump(mode="json") for h in sched_d1.history],
                },
                "d2_greedy": {
                    "actions_used": sched_d2.actions_used,
                    "bytes_used": sched_d2.bytes_used,
                    "history": [h.model_dump(mode="json") for h in sched_d2.history],
                },
                "a2_agent_planner": {
                    "actions_used": sched_a2.actions_used,
                    "bytes_used": sched_a2.bytes_used,
                    "history": [h.model_dump(mode="json") for h in sched_a2.history],
                },
            })

    report_path = out_dir / "e2_pilot_summary.json"
    report_path.write_text(json.dumps(e2_results, indent=2, sort_keys=True), encoding="utf-8")
    print("=" * 110)
    print(f"E2 Summary Report saved to {report_path}")


if __name__ == "__main__":
    main()
