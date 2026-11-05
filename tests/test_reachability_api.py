"""Pilot artifacts remain distinct from target SBOM and invalid results fail closed."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ui import reachability_api


class ReachabilityAPITests(unittest.TestCase):
    def test_missing_runtime_campaign_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(reachability_api, "RUNS", Path(directory)):
            result = reachability_api.latest()
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertNotIn("summary", result)

    def test_incomplete_or_symlinked_campaign_does_not_become_evidence(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(reachability_api, "RUNS", Path(directory)):
            root = Path(directory)
            (root / "level23-pilot-v1").mkdir()
            (root / "level23-pilot-v1/summary.json").write_text('{}')
            (root / "level23-pilot-v2").symlink_to(root / "level23-pilot-v1", target_is_directory=True)
            self.assertEqual(reachability_api.latest()["status"], "UNAVAILABLE")

    def test_invalid_newer_campaign_is_not_hidden_by_older_success(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(reachability_api, "RUNS", Path(directory)):
            for version in [1, 10]:
                root = Path(directory) / ("level23-pilot-v" + str(version))
                root.mkdir(); (root / "summary.json").write_text('{}'); (root / "seal.json").write_text('{}')
            with patch.object(reachability_api, "verify", side_effect=ValueError("changed evidence")) as verify:
                with self.assertRaises(ValueError): reachability_api.latest()
            self.assertEqual(verify.call_args.args[0].name, "level23-pilot-v10")


if __name__ == "__main__": unittest.main()
