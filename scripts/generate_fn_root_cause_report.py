#!/usr/bin/env python3
"""Generate failure attribution from measured paired interventions, never hard-coded edges."""
import argparse
import csv
import json
from pathlib import Path


def measured_failures(path):
    report = json.loads(Path(path).read_text())
    return [{**row, "data_kind": report["data_kind"], "protocol": report["protocol"]}
            for row in report["failure_decomposition"]]


def write_report(repair, output):
    rows = measured_failures(repair)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({key for row in rows for key in row})
    with output.open("x", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return rows


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repair", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    write_report(a.repair, a.out)
