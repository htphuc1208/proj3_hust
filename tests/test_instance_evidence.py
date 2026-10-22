"""Ambiguity must survive the evidence interface; synthetic controls only."""
from unittest import TestCase
from unittest.mock import patch

from sbom_recovery.instance_evidence import describe_instances


class InstanceEvidenceTests(TestCase):
    def test_singleton_lock_group_does_not_become_individual_binding(self):
        self.check_group(["one"])

    def test_all_repeated_physical_candidates_are_retained(self):
        self.check_group([f"instance-{i}" for i in range(37)])

    def check_group(self, ids):
        catalog = {"target_id": "fixture", "entries": [
            {"evidence_id": key, "path": f"{key}/package.json", "sha256": key} for key in ids]}
        matches = {"records": [{"ref": "scanner", "status": "LOCK_CORROBORATED_COORDINATE_GROUP",
                              "evidence_id": None, "coordinate_group_evidence_ids": ids}]}
        with patch("sbom_recovery.instance_evidence.match_files", return_value=matches), patch(
                "sbom_recovery.instance_evidence.read_identity", return_value={"purl": "pkg:npm/example@1"}):
            result = describe_instances({}, catalog, "/unused")
        row = result["records"][0]
        self.assertEqual(row["candidate_count"], len(ids))
        self.assertEqual([c["evidence_id"] for c in row["candidates"]], ids)
        self.assertIsNone(row["selected_instance"])
        self.assertEqual(row["dependency_edges"], "NOT_INFERRED")
