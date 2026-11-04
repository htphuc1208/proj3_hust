"""Unit tests for Agent Adjudicator A1."""
from __future__ import annotations

import unittest
from sbom_recovery.canonical import CanonicalClaim, CanonicalLedger, EvidenceItem
from sbom_recovery.agent_adjudicator import AgentAdjudicator


class TestAgentAdjudicator(unittest.TestCase):
    def test_adjudicate_root_vs_example_version(self):
        c1 = CanonicalClaim(
            case_id="case-adj",
            subject="pkg:pypi/flask",
            predicate="version",
            object="2.3.2",
            evidence=[EvidenceItem(source_id="syft", source_type="scanner_sbom", locator="examples/celery/requirements.txt")],
        )
        c2 = CanonicalClaim(
            case_id="case-adj",
            subject="pkg:pypi/flask",
            predicate="version",
            object="3.2.0.dev0",
            evidence=[EvidenceItem(source_id="trivy", source_type="scanner_sbom", locator="uv.lock")],
        )

        decision = AgentAdjudicator.adjudicate_conflict(
            subject="pkg:pypi/flask",
            predicate="version",
            candidates=[c1, c2],
        )

        self.assertEqual(decision.status, "verified")
        self.assertEqual(decision.selected_object, "3.2.0.dev0")
        self.assertIn("root project manifest/lockfile", decision.rationale)

    def test_filter_ci_action_dependency(self):
        c1 = CanonicalClaim(
            case_id="case-adj",
            subject="pkg:maven/com.google.code.gson/gson",
            predicate="depends_on",
            object="pkg:github/actions/setup-java@v5.2.0",
            evidence=[EvidenceItem(source_id="syft", source_type="scanner_sbom", locator="/.github/workflows/build.yml")],
        )

        decision = AgentAdjudicator.adjudicate_conflict(
            subject="pkg:maven/com.google.code.gson/gson",
            predicate="depends_on",
            candidates=[c1],
        )

        self.assertEqual(decision.status, "unknown")
        self.assertIsNone(decision.selected_object)
        self.assertIn("CI workflow", decision.rationale)


if __name__ == "__main__":
    unittest.main()
