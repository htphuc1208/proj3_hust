#!/usr/bin/env python3
"""Unit tests for registry_provider.py and Anti-Leakage Isolation."""
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))

from registry_provider import (
    FrozenRegistryEvidenceProvider,
    SecurityIsolationViolation,
    build_evidence_snapshot
)


class TestRegistryProvider(unittest.TestCase):

    def test_frozen_snapshot_loading_and_integrity(self):
        snapshot_dir = ROOT / "fixtures" / "evidence_snapshot"
        provider = FrozenRegistryEvidenceProvider(snapshot_dir)
        self.assertIn("requests@2.31.0", provider.packages)

        reqs = provider.get_requirements("pkg:pypi/requests@2.31.0")
        self.assertIsNotNone(reqs)
        target_purls = [r.target_purl for r in reqs]
        self.assertIn("pkg:pypi/urllib3", target_purls)
        self.assertIn("pkg:pypi/certifi", target_purls)

    def test_missing_evidence_reports_none(self):
        snapshot_dir = ROOT / "fixtures" / "evidence_snapshot"
        provider = FrozenRegistryEvidenceProvider(snapshot_dir)
        # Unseen package should report None (EVIDENCE_UNAVAILABLE), not hallucinate
        self.assertIsNone(provider.get_requirements("pkg:pypi/unseen-package@9.9.9"))

    def test_anti_leakage_isolation_blocks_oracle_artifacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            # Create fake manifest inside a path containing "pip_inspect"
            leak_dir = tmp / "runs" / "pip_inspect_leak"
            leak_dir.mkdir(parents=True, exist_ok=True)
            manifest = leak_dir / "evidence_manifest.json"
            manifest.write_text('{"artifacts": []}', encoding="utf-8")

            # Must raise SecurityIsolationViolation
            with self.assertRaises(SecurityIsolationViolation):
                FrozenRegistryEvidenceProvider(leak_dir)

    def test_tampered_artifact_fails_sha256_integrity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            manifest_file = build_evidence_snapshot({
                "test-pkg@1.0.0": {"requires_dist": ["foo>=1.0"]}
            }, tmp)

            # Tamper with file
            tampered_file = tmp / "test-pkg-1.0.0.json"
            tampered_file.write_text('{"tampered": true}', encoding="utf-8")

            # Must fail integrity check
            with self.assertRaises(ValueError):
                FrozenRegistryEvidenceProvider(tmp, manifest_file)


if __name__ == "__main__":
    unittest.main()
