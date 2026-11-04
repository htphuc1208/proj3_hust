"""Unit tests for LiveAgentAdjudicator."""
from __future__ import annotations

import unittest
from sbom_recovery.canonical import CanonicalClaim, CanonicalLedger, EvidenceItem
from sbom_recovery.live_agent_adjudicator import LiveAgentAdjudicator


class TestLiveAgentAdjudicator(unittest.TestCase):
    def test_missing_api_key_fails_closed(self):
        adjudicator = LiveAgentAdjudicator(api_key=None)
        c1 = CanonicalClaim(case_id="c1", subject="pkg:pypi/a", predicate="version", object="1.0.0")
        c2 = CanonicalClaim(case_id="c1", subject="pkg:pypi/a", predicate="version", object="2.0.0")

        decision = adjudicator.adjudicate_conflict_live("c1", "pkg:pypi/a", "version", [c1, c2])
        self.assertEqual(decision["status"], "unknown")
        self.assertIn("NETMIND_API_KEY not provided", decision["rationale"])

    def test_resolve_ledger_unconflicted_passthrough(self):
        adjudicator = LiveAgentAdjudicator(api_key=None)
        ledger = CanonicalLedger(case_id="c1")
        ledger.add_claim(CanonicalClaim(case_id="c1", subject="pkg:pypi/a", predicate="version", object="1.0.0"))

        resolved = adjudicator.resolve_ledger_live(ledger)
        self.assertEqual(len(resolved.claims), 1)
        self.assertEqual(resolved.claims[0].object, "1.0.0")


if __name__ == "__main__":
    unittest.main()
