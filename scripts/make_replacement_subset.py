#!/usr/bin/env python3
"""Capture only the new replacement roots; merged cohort keeps the 96 complete builds."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

OLD_HIST = "runs/unrestricted-cohort-selection-v2/cohort.json"


def main():
    cohort_path = ROOT / "runs/unrestricted-cohort-replacement-v1/cohort.json"
    cohort = json.loads(cohort_path.read_text())
    old_count = len(json.loads((ROOT / OLD_HIST).read_text()).get("replacement_history", []))
    new_names = {h["replacement_name"] for h in cohort["replacement_history"][old_count:]
                 if isinstance(h, dict) and h.get("replacement_name")}
    projects = [p for p in cohort["projects"] if p["name"] in new_names]
    assert len(projects) == len(new_names), "replacement roots missing from project list"
    subset = dict(cohort)
    subset["projects"] = projects
    out = ROOT / "runs/unrestricted-cohort-replacement-v1/subset.json"
    out.write_text(json.dumps(subset))
    print("capturing:", sorted(new_names))


if __name__ == "__main__":
    main()
