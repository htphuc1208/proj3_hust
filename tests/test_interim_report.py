"""Checkpoint integrity and censoring contracts, not model-quality evidence."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from research_core import digest, load
from sbom_recovery.campaign import flat_scores
from sbom_recovery.formats import sha
from sbom_recovery.storage import save
from scripts.export_interim_sbom_report import (
    METHODS, completed_project_rows, paired_case, take_snapshot,
)


class InterimSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.study = self.root / "study"
        self.case = self.study / "test/raw/example/fixed/raw-0-11/budget-64/rep-0"
        self.out = self.root / "snapshot"
        save(self.study / "model-selection.json", {"status": "FROZEN", "test_labels_used": False})
        save(self.study / "test/raw/campaign.json", {"settings": {"methods": list(METHODS), "repetitions": 3}})
        observation = {"spdxVersion": "SPDX-2.3", "packages": []}
        evidence = {"sources": {}}
        save(self.case / "input.spdx.json", observation)
        save(self.case / "evidence_binding.json", evidence)
        evaluation = {key: {"f1": 0.} for key in (
            "new_metadata", "new_nodes", "new_edges", "whole_metadata", "whole_nodes", "whole_edges")}
        self.rows = []
        for method in METHODS:
            spec = {
                "method": method, "input_sha256": sha(observation), "context_sha256": "context",
                "evidence_input_sha256": sha(evidence), "implementation_sha256": "implementation",
                "input_preparation_sha256": "preparation", "input_origin": "RAW_GENERATOR_DISCREPANCY",
                "calibration_sha256": "calibration", "single_scanner": "syft", "budget": 64,
                "condition": "fixed", "family": "raw", "rate": 0., "mask_seed": 11, "repetition": 0,
            }
            arm = self.case / method
            save(arm / "prediction.spdx.json", observation)
            save(arm / "evaluation.json", evaluation)
            save(arm / "seal.json", {"spec": spec, "sealed_at": "2026-10-30T01:00:00Z",
                "prediction_sha256": digest(arm / "prediction.spdx.json"),
                "oracle_exposed_to_prediction_worker": False})
            self.rows.append({**spec, "project": "example", "partition": "test",
                "status": "MODEL_ERROR" if method == "single_agent" else "COMPLETE",
                "metrics": flat_scores(evaluation)})
        save(self.case / "records.json", {"records": self.rows})
        self.cutoff = datetime(2026, 10, 30, 2, 0, tzinfo=timezone.utc)

    def test_terminal_model_failure_remains_in_the_paired_snapshot(self):
        snapshot, _ = take_snapshot(self.study, self.out, self.cutoff)
        self.assertEqual(len(snapshot["included_cases"]), 1)
        rows = load(next(self.out.rglob("records.json")))["records"]
        self.assertEqual(len(rows), 7)
        self.assertEqual(next(r for r in rows if r["method"] == "single_agent")["status"], "MODEL_ERROR")

    def test_excludes_case_with_one_prediction_after_cutoff(self):
        path = self.case / "multi_agent/seal.json"
        seal = load(path); seal["sealed_at"] = "2026-10-30T02:00:01Z"; save(path, seal)
        snapshot, _ = take_snapshot(self.study, self.out, self.cutoff)
        self.assertEqual(snapshot["included_cases"], [])
        self.assertEqual(snapshot["omitted_cases"][0]["reason"], "SEALED_AFTER_CUTOFF")

    def test_rejects_changed_prediction(self):
        save(self.case / "single_agent/prediction.spdx.json", {"changed": True})
        with self.assertRaisesRegex(ValueError, "prediction changed"):
            take_snapshot(self.study, self.out, self.cutoff)

    def test_snapshot_survives_atomic_replacement_of_upstream_file(self):
        take_snapshot(self.study, self.out, self.cutoff)
        copy = next(self.out.rglob("single_agent/prediction.spdx.json"))
        before = copy.read_bytes()
        save(self.case / "single_agent/prediction.spdx.json", {"later revision": True})
        self.assertEqual(copy.read_bytes(), before)

    def test_incomplete_scoring_is_disclosed_instead_of_dropped_silently(self):
        (self.case / "single_agent/evaluation.json").unlink()
        snapshot, _ = take_snapshot(self.study, self.out, self.cutoff)
        self.assertEqual(snapshot["included_cases"], [])
        self.assertEqual(snapshot["omitted_cases"][0]["reason"], "SCORING_UNAVAILABLE")

    def test_paired_case_rejects_incomplete_panel_and_mismatched_evidence(self):
        with self.assertRaisesRegex(ValueError, "seven distinct"):
            paired_case(self.rows[:-1])
        changed = deepcopy(self.rows); changed[-1]["evidence_input_sha256"] = "other evidence"
        with self.assertRaisesRegex(ValueError, "different permitted"):
            paired_case(changed)

    def test_current_panel_needs_no_calibration_artifact(self):
        rows = [{k: v for k, v in row.items() if k != "calibration_sha256"}
                for row in self.rows]
        paired_case(rows)

    def test_historical_panel_still_checks_calibration_binding(self):
        changed = deepcopy(self.rows)
        changed[-1]["calibration_sha256"] = "other"
        with self.assertRaisesRegex(ValueError, "different permitted"):
            paired_case(changed)
        changed[-1].pop("calibration_sha256")
        with self.assertRaisesRegex(ValueError, "different permitted"):
            paired_case(changed)

    def test_three_repetitions_are_required_for_complete_project_panel(self):
        self.assertEqual(completed_project_rows(self.rows, 3), [])
        all_repetitions = [{**row, "repetition": rep} for rep in range(3) for row in self.rows]
        self.assertEqual(len(completed_project_rows(all_repetitions, 3)), 21)


if __name__ == "__main__":
    unittest.main()
