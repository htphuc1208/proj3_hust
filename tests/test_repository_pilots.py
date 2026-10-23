#!/usr/bin/env python3
"""Integration tests verifying the Real Repository Pilots and Artifact Provenance (M2.2 Final Validity Gate)."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TestRepositoryPilotsAndArtifactProvenance(unittest.TestCase):

    def test_artifact_level_evidence_manifest_provenance(self):
        """P0.1: Verify artifact-level provenance chain for all frozen evidence."""
        manifest_path = ROOT / "fixtures" / "evidence_snapshot" / "evidence_manifest.json"
        self.assertTrue(manifest_path.exists(), "Manifest must exist")
        data = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(data.get("schema_version"), "evidence-manifest-v3-artifact-verified")
        self.assertEqual(data.get("provenance_chain"), "PyPI index -> Distribution artifact -> Verified SHA-256 -> Extracted METADATA -> Frozen evidence record")
        self.assertGreaterEqual(len(data.get("artifacts", [])), 48)

        # Spot check critical packages
        requests_rec = next(a for a in data["artifacts"] if a["name"] == "requests" and a["version"] == "2.31.0")
        self.assertTrue(requests_rec["artifact_verified"])
        self.assertTrue(len(requests_rec["wheel_sha256"]) == 64)
        self.assertTrue(len(requests_rec["wheel_metadata_sha256"]) == 64)

        # Check individual artifact json
        req_json = json.loads((ROOT / "fixtures" / "evidence_snapshot" / requests_rec["metadata_file"]).read_text(encoding="utf-8"))
        self.assertEqual(req_json["provenance"]["verification_status"], "VERIFIED_ARTIFACT_DIGEST_AND_METADATA")
        self.assertTrue(req_json["artifact_level_metadata"]["wheel_bytes_verified"])

        crypto_rec = next(a for a in data["artifacts"] if a["name"] == "cryptography" and a["version"] == "41.0.5")
        self.assertTrue(crypto_rec["artifact_verified"])
        self.assertTrue(len(crypto_rec["wheel_sha256"]) == 64)

    def test_repository_pilots_results_invariants(self):
        """P0.5: Verify both repository pilots completed with strict invariants."""
        results_path = ROOT / "runs" / "real_repository_pilots.json"
        self.assertTrue(results_path.exists(), "Pilot results file must exist")
        pilots = json.loads(results_path.read_text(encoding="utf-8"))
        self.assertEqual(len(pilots), 2)

        pilot_names = {p["repository"] for p in pilots}
        self.assertEqual(pilot_names, {"requests-cache", "httpbin"})

        for p in pilots:
            repo = p["repository"]
            b = p["baselines_on_degraded_sbom"]
            # This is a historical ledger, not a universal performance invariant.
            for arm, counts in b.items():
                for field in ("tp", "fp", "fn"):
                    self.assertIsInstance(counts[field], int)
                    self.assertGreaterEqual(counts[field], 0)

            # Baseline order: B1 (context-free) has FP due to inactive extras
            self.assertGreater(b["B1_Context_Free"]["fp"], 0, f"B1 must exhibit FPs on {repo} due to unconstrained extras")

            # Generator discrepancy taxonomy check:
            cdx = p["generator_discrepancy_and_scope_analysis"]["cyclonedx_py"]
            self.assertIn("CROSS_TOOL_IDENTITY_NORMALIZATION_REQUIRED", cdx["taxonomy_classification"])
            self.assertGreater(cdx["direct_app_edges_reported"], 0)

            syft = p["generator_discrepancy_and_scope_analysis"]["anchore_syft"]
            self.assertEqual(syft["direct_app_edges_reported"], 0)
            self.assertIn("Filesystem / Artifact Inventory Scope", syft["scope_analysis"]["scope_type"])


if __name__ == "__main__":
    unittest.main()
