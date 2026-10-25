#!/usr/bin/env python3
"""Unit tests verifying Temporal Protocol & Anti-Look-Ahead Invariants (M2.3)."""
from datetime import datetime, timezone
import unittest


class TemporalCandidateFilter:
    """Utility class implementing candidate filtering under the 4-timestamp protocol."""

    @staticmethod
    def filter_candidates_by_cutoff(candidates, cutoff_utc):
        """Filter candidate releases by cutoff timestamp."""
        admitted = []
        for c in candidates:
            rel_time = datetime.fromisoformat(c["upload_time_utc"].replace("Z", "+00:00"))
            if rel_time <= cutoff_utc:
                admitted.append(c)
        return admitted

    @staticmethod
    def classify_advisory_triage(advisory_published_utc, install_time_utc):
        """Classify vulnerability triage modality."""
        if advisory_published_utc <= install_time_utc:
            return "KNOWN_AT_INSTALLATION"
        return "RETROSPECTIVE_SECURITY_ASSESSMENT"


class TestTemporalProtocol(unittest.TestCase):

    def setUp(self):
        # Simulated release times
        self.t_release_requests_2_31_0 = datetime.fromisoformat("2023-05-22T14:00:00+00:00")
        self.t_install_contemporary = datetime.fromisoformat("2026-10-22T07:00:00+00:00")
        self.t_install_historical = datetime.fromisoformat("2023-06-01T00:00:00+00:00")

        self.certifi_candidates = [
            {"version": "2023.7.22", "upload_time_utc": "2023-07-22T12:00:00Z"},
            {"version": "2024.2.2", "upload_time_utc": "2024-02-20T10:00:00Z"},
            {"version": "2026.10.19", "upload_time_utc": "2026-10-19T08:00:00Z"},
            {"version": "2027.1.1", "upload_time_utc": "2027-01-01T00:00:00Z"}, # Future look-ahead
        ]

    def test_contemporary_installation_admits_newer_dependencies(self):
        """P0: Contemporary installation (2026) must admit dependencies published after parent release (2023)."""
        admitted = TemporalCandidateFilter.filter_candidates_by_cutoff(
            self.certifi_candidates, self.t_install_contemporary
        )
        admitted_versions = [c["version"] for c in admitted]

        # 2024.2.2 was released after requests==2.31.0 (2023), but BEFORE installation (2026)
        self.assertIn("2024.2.2", admitted_versions)
        self.assertIn("2026.10.19", admitted_versions)
        # Future package must be excluded
        self.assertNotIn("2027.1.1", admitted_versions)

    def test_historical_installation_blocks_future_dependencies(self):
        """P0: Historical installation (2023) must strictly block dependencies published after historical cutoff."""
        admitted = TemporalCandidateFilter.filter_candidates_by_cutoff(
            self.certifi_candidates, self.t_install_historical
        )
        admitted_versions = [c["version"] for c in admitted]

        # In June 2023, neither 2023.7.22, 2024.2.2, nor 2026.10.19 existed
        self.assertNotIn("2023.7.22", admitted_versions)
        self.assertNotIn("2024.2.2", admitted_versions)
        self.assertNotIn("2026.10.19", admitted_versions)

    def test_advisory_classification_distinguishes_retrospective_assessment(self):
        """P0: Security assessment must label vulnerabilities discovered after installation as RETROSPECTIVE."""
        # Advisory published Oct 25, 2023
        t_advisory_ghsa = datetime.fromisoformat("2023-10-25T18:00:00+00:00")

        # Case 1: Assessed against historic deployment from June 2023
        modality_hist = TemporalCandidateFilter.classify_advisory_triage(
            t_advisory_ghsa, self.t_install_historical
        )
        self.assertEqual(modality_hist, "RETROSPECTIVE_SECURITY_ASSESSMENT")

        # Case 2: Assessed against contemporary deployment from Oct 2026
        modality_contemp = TemporalCandidateFilter.classify_advisory_triage(
            t_advisory_ghsa, self.t_install_contemporary
        )
        self.assertEqual(modality_contemp, "KNOWN_AT_INSTALLATION")


if __name__ == "__main__":
    unittest.main()
