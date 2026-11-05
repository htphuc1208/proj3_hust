"""Unit tests for Experiment E1 Decision Engine."""
from __future__ import annotations

import unittest
from sbom_recovery.canonical import CanonicalClaim, CanonicalLedger, EvidenceItem
from sbom_recovery.e1_experiment import E1DecisionEngine


class TestE1Experiment(unittest.TestCase):
    def test_b0_priority_resolution(self):
        ledger = CanonicalLedger(case_id="case-e1")
        # Tool syft claims version 1.0.0
        c1 = CanonicalClaim(
            case_id="case-e1",
            subject="pkg:pypi/demo",
            predicate="version",
            object="1.0.0",
            evidence=[EvidenceItem(source_id="syft", source_type="scanner_sbom", locator="pkg")],
        )
        # Tool manifest_spdx claims version 2.0.0
        c2 = CanonicalClaim(
            case_id="case-e1",
            subject="pkg:pypi/demo",
            predicate="version",
            object="2.0.0",
            evidence=[EvidenceItem(source_id="manifest_spdx", source_type="scanner_sbom", locator="pkg")],
        )
        ledger.add_claim(c1)
        ledger.add_claim(c2)

        res = E1DecisionEngine.resolve_b0_priority(ledger)
        self.assertEqual(res.conflict_decisions, 1)
        chosen = res.resolved_ledger.get_claims(subject="pkg:pypi/demo", predicate="version")
        self.assertEqual(len(chosen), 1)
        # manifest_spdx has higher priority than syft in sbom-unifier order
        self.assertEqual(chosen[0].object, "2.0.0")

    def test_b1_majority_resolution(self):
        ledger = CanonicalLedger(case_id="case-e1")
        c1 = CanonicalClaim(
            case_id="case-e1",
            subject="pkg:pypi/demo",
            predicate="licenseDeclared",
            object="MIT",
            evidence=[EvidenceItem(source_id="syft", source_type="scanner_sbom", locator="l1")],
        )
        c2 = CanonicalClaim(
            case_id="case-e1",
            subject="pkg:pypi/demo",
            predicate="licenseDeclared",
            object="MIT",
            evidence=[EvidenceItem(source_id="trivy", source_type="scanner_sbom", locator="l2")],
        )
        c3 = CanonicalClaim(
            case_id="case-e1",
            subject="pkg:pypi/demo",
            predicate="licenseDeclared",
            object="Apache-2.0",
            evidence=[EvidenceItem(source_id="manifest_spdx", source_type="scanner_sbom", locator="l3")],
        )
        ledger.add_claim(c1)
        ledger.add_claim(c2)
        ledger.add_claim(c3)

        res = E1DecisionEngine.resolve_b1_majority(ledger)
        chosen = res.resolved_ledger.get_claims(subject="pkg:pypi/demo", predicate="licenseDeclared")
        self.assertEqual(len(chosen), 1)
        # 2 votes for MIT vs 1 vote for Apache-2.0
        self.assertEqual(chosen[0].object, "MIT")

    def test_b2_field_aware_rules_and_abstention(self):
        ledger = CanonicalLedger(case_id="case-e1")
        # Version conflict: 'latest' vs '2.31.0'
        c1 = CanonicalClaim(
            case_id="case-e1",
            subject="pkg:pypi/requests",
            predicate="version",
            object="latest",
            evidence=[EvidenceItem(source_id="manifest_spdx", source_type="scanner_sbom", locator="pkg")],
        )
        c2 = CanonicalClaim(
            case_id="case-e1",
            subject="pkg:pypi/requests",
            predicate="version",
            object="2.31.0",
            evidence=[EvidenceItem(source_id="syft", source_type="scanner_sbom", locator="pkg")],
        )
        # CI workflow relationship injected erroneously
        c3 = CanonicalClaim(
            case_id="case-e1",
            subject="pkg:pypi/requests",
            predicate="depends_on",
            object="pkg:github/actions/setup-python@v4",
            evidence=[EvidenceItem(source_id="syft", source_type="scanner_sbom", locator="rel")],
        )
        ledger.add_claim(c1)
        ledger.add_claim(c2)
        ledger.add_claim(c3)

        res = E1DecisionEngine.resolve_b2_field_aware(ledger)
        # Concrete version selected over 'latest'
        ver_claim = res.resolved_ledger.get_claims(subject="pkg:pypi/requests", predicate="version")
        self.assertEqual(len(ver_claim), 1)
        self.assertEqual(ver_claim[0].object, "2.31.0")

        # CI action filtered out from dependency relationships
        dep_claims = res.resolved_ledger.get_claims(subject="pkg:pypi/requests", predicate="depends_on")
        self.assertEqual(len(dep_claims), 0)


if __name__ == "__main__":
    unittest.main()
