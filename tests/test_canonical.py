"""Unit tests for Canonical Claim and Evidence Ledger contracts."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sbom_recovery.canonical import (
    CanonicalClaim,
    CanonicalLedger,
    EvidenceItem,
    VerificationRecord,
    compute_claim_id,
)


class TestCanonical(unittest.TestCase):
    def test_canonical_claim_id_deterministic(self):
        claim1 = CanonicalClaim(
            case_id="pilot-001",
            subject="pkg:pypi/requests@2.31.0",
            predicate="version",
            object="2.31.0",
            layer="G2_resolved",
            scope="runtime_production",
            status="verified",
        )
        self.assertTrue(claim1.claim_id)
        expected = compute_claim_id(
            case_id="pilot-001",
            subject="pkg:pypi/requests@2.31.0",
            predicate="version",
            object_val="2.31.0",
            layer="G2_resolved",
            scope="runtime_production",
        )
        self.assertEqual(claim1.claim_id, expected)

    def test_ledger_add_and_merge_evidence(self):
        ledger = CanonicalLedger(case_id="pilot-001")
        claim1 = CanonicalClaim(
            case_id="pilot-001",
            subject="pkg:pypi/requests@2.31.0",
            predicate="version",
            object="2.31.0",
            layer="G3_artifact",
            scope="runtime_production",
            evidence=[
                EvidenceItem(
                    source_id="syft",
                    source_type="scanner_sbom",
                    locator="SPDXRef-Package-1",
                    raw_value="2.31.0",
                )
            ],
        )
        ledger.add_claim(claim1)
        self.assertEqual(len(ledger.claims), 1)

        # Same claim, different evidence source
        claim2 = CanonicalClaim(
            case_id="pilot-001",
            subject="pkg:pypi/requests@2.31.0",
            predicate="version",
            object="2.31.0",
            layer="G3_artifact",
            scope="runtime_production",
            evidence=[
                EvidenceItem(
                    source_id="wheel_metadata",
                    source_type="installed_artifact_metadata",
                    locator="METADATA:Version",
                    raw_value="2.31.0",
                )
            ],
        )
        ledger.add_claim(claim2)
        # Should not duplicate claim, but merge evidence
        self.assertEqual(len(ledger.claims), 1)
        self.assertEqual(len(ledger.claims[0].evidence), 2)

    def test_conflict_detection(self):
        ledger = CanonicalLedger(case_id="pilot-001")
        # Tool A claims version is 2.31.0
        c1 = CanonicalClaim(
            case_id="pilot-001",
            subject="pkg:pypi/requests@2.31.0",
            predicate="version",
            object="2.31.0",
            layer="G2_resolved",
            scope="runtime_production",
            evidence=[EvidenceItem(source_id="syft", source_type="scanner_sbom", locator="pkg1")],
        )
        # Tool B claims version is 2.30.0
        c2 = CanonicalClaim(
            case_id="pilot-001",
            subject="pkg:pypi/requests@2.31.0",
            predicate="version",
            object="2.30.0",
            layer="G2_resolved",
            scope="runtime_production",
            evidence=[EvidenceItem(source_id="trivy", source_type="scanner_sbom", locator="pkg2")],
        )
        ledger.add_claim(c1)
        ledger.add_claim(c2)

        conflicts = ledger.find_conflicts()
        self.assertIn(("pkg:pypi/requests@2.31.0", "version"), conflicts)
        self.assertEqual(len(conflicts[("pkg:pypi/requests@2.31.0", "version")]), 2)

    def test_serialization_roundtrip(self):
        ledger = CanonicalLedger(case_id="pilot-001")
        c = CanonicalClaim(
            case_id="pilot-001",
            subject="pkg:pypi/requests@2.31.0",
            predicate="depends_on",
            object="pkg:pypi/urllib3@2.0.7",
            layer="G2_resolved",
            scope="runtime_production",
            status="verified",
            verification=VerificationRecord(
                method="native_dry_run_resolver",
                review_status="accepted",
            ),
        )
        ledger.add_claim(c)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "ledger.json"
            ledger.save(out_path)
            loaded = CanonicalLedger.load(out_path)
            self.assertEqual(loaded.case_id, ledger.case_id)
            self.assertEqual(len(loaded.claims), 1)
            self.assertEqual(loaded.claims[0].object, "pkg:pypi/urllib3@2.0.7")
            self.assertEqual(loaded.fingerprint(), ledger.fingerprint())


if __name__ == "__main__":
    unittest.main()
