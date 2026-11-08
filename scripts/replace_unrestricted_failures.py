#!/usr/bin/env python3
"""Freeze fixed-ranked build-failure replacements without reading method scores."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from research_core import digest, load, now
from sbom_recovery.fresh_selection import replace_failed
from sbom_recovery.storage import save


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", required=True, help="Path to parent cohort JSON")
    parser.add_argument("--captures", required=True, help="Path to captures directory")
    parser.add_argument("--validation", default=None, help="Optional validation manifest JSON")
    parser.add_argument("--out", required=True, help="Output directory")

    args = parser.parse_args()
    parent = load(args.cohort)
    captures = Path(args.captures)

    val_records = {}
    if args.validation and Path(args.validation).exists():
        vdata = load(args.validation)
        val_records = {r["project"]: r for r in vdata.get("records", [])}

    outcomes = {}
    for row in parent["projects"]:
        path = captures / row["name"] / "capture.json"
        if not path.exists():
            raise ValueError(f"Unreported capture: {row['name']}")
        report = load(path)
        if report["project"]["version"] != row["version"]:
            raise ValueError(f"Capture version mismatch for project {row['name']}")

        val = val_records.get(row["name"])
        if val and val.get("status") != "PASSED":
            status = "OBSERVATION_INVALID"
            evidence = digest(args.validation)
        else:
            status = report["status"]
            evidence = digest(path)

        outcomes[row["name"]] = {"status": status, "evidence_sha256": evidence}

    revised = replace_failed(parent, outcomes)
    revised.update(
        parent_cohort_sha256=digest(args.cohort),
        created_at=now(),
        replacement_source_sha256=digest(ROOT / "sbom_recovery/fresh_selection.py"),
    )

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=False)
    save(out / "cohort.json", revised)
    save(out / "eligibility-inputs.json", outcomes)

    shutil.copyfile(__file__, out / "executed-runner.py")
    shutil.copyfile(ROOT / "sbom_recovery/fresh_selection.py", out / "executed-selection.py")

    new_replacements_count = len(revised["replacement_history"]) - len(parent.get("replacement_history", []))
    print(revised["status"], "new replacements", new_replacements_count)


if __name__ == "__main__":
    main()
