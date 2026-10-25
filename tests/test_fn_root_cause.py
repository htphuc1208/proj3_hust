#!/usr/bin/env python3
"""Regression tests verifying the 10 False Negative root-cause classifications (M2.3)."""
import csv
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TestFNRootCauseReport(unittest.TestCase):

    def test_report_exists_and_covers_all_ten_fns(self):
        csv_file = ROOT / "fn_root_cause_report.csv"
        self.assertTrue(csv_file.exists(), "fn_root_cause_report.csv must exist")

        with open(csv_file, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        self.assertEqual(len(rows), 10, "Must contain exactly 10 False Negative records")

        reqcache_fns = [r for r in rows if r["project"] == "requests-cache"]
        httpbin_fns = [r for r in rows if r["project"] == "httpbin"]

        self.assertEqual(len(reqcache_fns), 4)
        self.assertEqual(len(httpbin_fns), 6)

        # Invariant 1: requests-cache FNs stem from requests==2.34.2 missing in frozen snapshot
        for r in reqcache_fns:
            self.assertEqual(r["parent_purl"], "pkg:pypi/requests@2.34.2")
            self.assertEqual(r["root_cause_classification"], "EVIDENCE_UNAVAILABLE")

        # Invariant 2: httpbin FNs stem from flasgger==0.9.7.1 having sdist-only build without registry wheel metadata
        for r in httpbin_fns:
            self.assertEqual(r["parent_purl"], "pkg:pypi/flasgger@0.9.7.1")
            self.assertEqual(r["root_cause_classification"], "ARTIFACT_METADATA_MISMATCH")


if __name__ == "__main__":
    unittest.main()
