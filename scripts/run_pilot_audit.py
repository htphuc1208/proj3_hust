"""Runner script to audit 9 pilot projects and analyze tool conflicts."""
from __future__ import annotations

import json
from pathlib import Path

from sbom_recovery.pilot_audit import audit_pilot_cohort


def main():
    replication_root = Path("research/.work/sbom-unifier-replication")
    out_dir = Path("runs/pilot-audit-v1")
    out_dir.mkdir(parents=True, exist_ok=True)
    ledgers_dir = out_dir / "ledgers"
    ledgers_dir.mkdir(parents=True, exist_ok=True)
    configs_dir = Path("configs")
    configs_dir.mkdir(parents=True, exist_ok=True)

    print("Auditing 9 pilot projects from replication root...")
    cohort, ledgers = audit_pilot_cohort(replication_root)

    # 1. Save cohort manifest
    cohort_json = {k: v.model_dump(mode="json") for k, v in cohort.items()}
    cohort_file = configs_dir / "pilot_9_cohort.json"
    cohort_file.write_text(json.dumps(cohort_json, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Saved cohort manifest to {cohort_file}")

    # 2. Save ledgers and analyze conflicts
    summary_report = []

    print("\n" + "=" * 80)
    print("PILOT COHORT AUDIT & CONFLICT ANALYSIS (3 Python, 3 Java, 3 JavaScript)")
    print("=" * 80)

    for case_id, meta in cohort.items():
        ledger = ledgers[case_id]
        ledger_path = ledgers_dir / f"{case_id}.json"
        ledger.save(ledger_path)

        conflicts = ledger.find_conflicts()
        total_claims = len(ledger.claims)
        
        # Tools stats
        tool_counts = {t: d.package_count for t, d in meta.tool_sboms.items()}
        
        report_item = {
            "case_id": case_id,
            "language": meta.language,
            "project": meta.project,
            "total_claims": total_claims,
            "conflict_count": len(conflicts),
            "tool_package_counts": tool_counts,
            "sample_conflicts": []
        }

        print(f"\n[{case_id}] ({meta.language.upper()} / {meta.ecosystem.upper()}) - {meta.project}")
        print(f"  Repo: {meta.repository_url} (pushed: {meta.pushed_at})")
        print(f"  Tool Packages: {tool_counts}")
        print(f"  Total Extracted Claims: {total_claims}")
        print(f"  Conflicting (subject, predicate) pairs: {len(conflicts)}")

        for (subj, pred), clist in list(conflicts.items())[:5]:
            obj_sources = [(c.object, [e.source_id for e in c.evidence]) for c in clist]
            report_item["sample_conflicts"].append({
                "subject": subj,
                "predicate": pred,
                "variants": obj_sources
            })
            print(f"    * Conflict on '{pred}' for {subj}:")
            for obj, sources in obj_sources:
                print(f"        -> '{obj}' reported by {sources}")

        summary_report.append(report_item)

    report_file = out_dir / "pilot_conflict_summary.json"
    report_file.write_text(json.dumps(summary_report, indent=2, sort_keys=True), encoding="utf-8")
    print("\n" + "=" * 80)
    print(f"Summary report saved to {report_file}")
    print("=" * 80)


if __name__ == "__main__":
    main()
