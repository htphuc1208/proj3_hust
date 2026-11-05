"""Unit tests for Canonical Claim Scorer."""
from __future__ import annotations

import unittest
from sbom_recovery.canonical import CanonicalClaim, CanonicalLedger, EvidenceItem
from sbom_recovery.claim_scorer import ClaimScorer


class TestClaimScorer(unittest.TestCase):
    def test_claim_scorer_metrics(self):
        gold = CanonicalLedger(case_id="case-test")
        gold.add_claim(CanonicalClaim(case_id="case-test", subject="pkg:pypi/a", predicate="version", object="1.0.0"))
        gold.add_claim(CanonicalClaim(case_id="case-test", subject="pkg:pypi/b", predicate="version", object="2.0.0"))

        input_ledger = CanonicalLedger(case_id="case-test")
        # Conflict on package a: Tool 1 says 1.0.0, Tool 2 says 1.0.1
        input_ledger.add_claim(CanonicalClaim(case_id="case-test", subject="pkg:pypi/a", predicate="version", object="1.0.0", evidence=[EvidenceItem(source_id="s1", source_type="scanner_sbom", locator="l1")]))
        input_ledger.add_claim(CanonicalClaim(case_id="case-test", subject="pkg:pypi/a", predicate="version", object="1.0.1", evidence=[EvidenceItem(source_id="s2", source_type="scanner_sbom", locator="l2")]))
        # Clean on package b: says 2.0.0
        input_ledger.add_claim(CanonicalClaim(case_id="case-test", subject="pkg:pypi/b", predicate="version", object="2.0.0", evidence=[EvidenceItem(source_id="s1", source_type="scanner_sbom", locator="l3")]))

        # Prediction: got 'a' right, got 'b' right
        pred = CanonicalLedger(case_id="case-test")
        pred.add_claim(CanonicalClaim(case_id="case-test", subject="pkg:pypi/a", predicate="version", object="1.0.0"))
        pred.add_claim(CanonicalClaim(case_id="case-test", subject="pkg:pypi/b", predicate="version", object="2.0.0"))

        report = ClaimScorer.evaluate_case(
            case_id="case-test",
            strategy="test_strategy",
            gold_ledger=gold,
            input_ledger=input_ledger,
            predicted_ledger=pred,
        )

        self.assertEqual(report.overall_metrics.precision, 1.0)
        self.assertEqual(report.overall_metrics.recall, 1.0)
        self.assertEqual(report.far, 0.0)
        self.assertEqual(report.vrr, 1.0)  # Package 'a' was imperfect in input and correctly recovered
        self.assertEqual(report.conflict_metrics.total_conflicts, 1)
        self.assertEqual(report.conflict_metrics.correct_resolutions, 1)
        self.assertEqual(report.conflict_metrics.accuracy_on_covered, 1.0)

    def test_abstention_and_false_assertion_rate(self):
        gold = CanonicalLedger(case_id="case-test")
        gold.add_claim(CanonicalClaim(case_id="case-test", subject="pkg:pypi/a", predicate="version", object="1.0.0"))

        input_ledger = CanonicalLedger(case_id="case-test")
        input_ledger.add_claim(CanonicalClaim(case_id="case-test", subject="pkg:pypi/a", predicate="version", object="1.0.0", evidence=[EvidenceItem(source_id="s1", source_type="scanner_sbom", locator="l1")]))
        input_ledger.add_claim(CanonicalClaim(case_id="case-test", subject="pkg:pypi/a", predicate="version", object="2.0.0", evidence=[EvidenceItem(source_id="s2", source_type="scanner_sbom", locator="l2")]))

        # Prediction abstained
        pred = CanonicalLedger(case_id="case-test")
        pred.add_claim(CanonicalClaim(case_id="case-test", subject="pkg:pypi/a", predicate="version", object="unknown", status="unknown"))

        report = ClaimScorer.evaluate_case(
            case_id="case-test",
            strategy="test_abstain",
            gold_ledger=gold,
            input_ledger=input_ledger,
            predicted_ledger=pred,
        )

        self.assertEqual(report.total_abstained, 1)
        self.assertEqual(report.coverage, 0.0)
        self.assertEqual(report.far, 0.0)  # No false assertions because it abstained!
        self.assertEqual(report.conflict_metrics.abstentions, 1)


if __name__ == "__main__":
    unittest.main()
