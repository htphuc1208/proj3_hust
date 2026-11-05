"""Integrity checks for reporting; fixtures do not measure recovery quality."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from research_core import digest
from sbom_recovery.campaign import flat_scores
from sbom_recovery.contracts import TargetContext
from sbom_recovery.formats import sha
from sbom_recovery.storage import save
from scripts.analyze_completed_sbom_runs import (
    METHODS, assert_paired_inputs, audited_records,
)


def paired_rows():
    agent = {
        "project": "fixture", "method": "single_agent", "condition": "fixed",
        "budget": 64, "family": "metadata", "rate": .5, "mask_seed": 11,
        "repetition": 0, "input_sha256": "input", "context_sha256": "context",
        "evidence_input_sha256": "evidence", "implementation_sha256": "implementation",
        "single_scanner": "syft",
    }
    return [agent], [{**agent, "method": method} for method in METHODS]


class PairingIntegrityTests(unittest.TestCase):
    def test_accepts_complete_pairing_and_rejects_changed_implementation(self):
        agents, controls = paired_rows()
        assert_paired_inputs(agents, controls)
        controls[0]["implementation_sha256"] = "other source"
        with self.assertRaisesRegex(ValueError, "Incomparable"):
            assert_paired_inputs(agents, controls)

    def test_equal_missing_bindings_do_not_establish_comparability(self):
        agents, controls = paired_rows()
        for row in agents + controls:
            row.pop("evidence_input_sha256")
        with self.assertRaisesRegex(ValueError, "Incomparable"):
            assert_paired_inputs(agents, controls)

    def test_rejects_duplicate_agent_and_unpaired_extra_control(self):
        agents, controls = paired_rows()
        with self.assertRaisesRegex(ValueError, "Duplicate agent"):
            assert_paired_inputs(agents + deepcopy(agents), controls)
        with self.assertRaisesRegex(ValueError, "Unpaired extra"):
            assert_paired_inputs(agents, controls + [{**controls[0], "project": "other"}])


class SealedAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.run = root / "run"
        self.case = self.run / "fixture/fixed/metadata-0.5-11/budget-64/rep-0"
        self.arm = self.case / "single_agent"
        self.capture = root / "captures/fixture"
        self.context = TargetContext(
            os_name="posix", sys_platform="linux", platform_machine="x86_64",
            python_version="3.11", python_full_version="3.11.16", platform_system="Linux",
            active_extras=[], target_id="fixture-target", evidence_cutoff="2026-10-28T00:00:00Z",
            root_purls=["pkg:pypi/fixture@1"],
        )
        save(self.capture / "context.json", self.context.model_dump())
        save(self.capture / "capture.json", {
            "project": {"name": "fixture", "version": "1"},
            "historical_resolution_horizon": self.context.evidence_cutoff,
        })
        for name in ("installed_reference.cdx.json", "installed_reference.json", "installed_field_labels.json"):
            save(self.capture / "oracle" / name, {"fixture": True})
        self.observation = {"spdxVersion": "SPDX-2.3", "packages": []}
        self.evidence = {"sources": {}}
        save(self.case / "input.spdx.json", self.observation)
        save(self.case / "evidence_binding.json", self.evidence)
        save(self.arm / "prediction.spdx.json", self.observation)
        self.evaluation = {key: {"f1": 0.} for key in (
            "new_metadata", "new_edges", "new_nodes", "whole_metadata", "whole_edges", "whole_nodes",
        )}
        self.evaluation.update({key: [] for key in (
            "false_positive_nodes", "missed_nodes", "false_positive_edges", "missed_edges",
            "false_positive_metadata", "missed_metadata",
        )})
        self.evaluation["failure_taxonomy"] = {key: [] for key in ("A", "B", "C", "D", "E", "UNRESOLVED")}
        save(self.arm / "evaluation.json", self.evaluation)
        self.spec = {
            "method": "single_agent", "model": "fixture-model", "budget": 64,
            "condition": "fixed", "family": "metadata", "rate": .5,
            "input_sha256": sha(self.observation), "context_sha256": sha(self.context.model_dump()),
            "evidence_input_sha256": sha(self.evidence),
        }
        self.row = {**self.spec, "project": "fixture", "status": "COMPLETE", "case": str(self.case), "metrics": flat_scores(self.evaluation)}
        save(self.case / "records.json", {"records": [self.row]})
        save(self.arm / "seal.json", {
            "spec": self.spec, "prediction_sha256": digest(self.arm / "prediction.spdx.json"),
            "oracle_exposed_to_prediction_worker": False,
        })
        save(self.run / "campaign.json", {
            "status": "COMPLETE", "settings": {"captures": str(self.capture.parent)},
        })
        self.scoring = patch("scripts.analyze_completed_sbom_runs.score_after_seal", return_value=self.evaluation)
        self.scoring.start()
        self.addCleanup(self.scoring.stop)

    def test_accepts_reproducible_scores_without_modifying_prediction(self):
        before = (self.arm / "prediction.spdx.json").read_bytes()
        rows, audit = audited_records(self.run)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(audit["evaluation_sha256"]), 1)
        self.assertEqual(before, (self.arm / "prediction.spdx.json").read_bytes())

    def test_rejects_prediction_changed_after_seal(self):
        save(self.arm / "prediction.spdx.json", {**self.observation, "name": "changed"})
        with self.assertRaisesRegex(ValueError, "Prediction changed"):
            audited_records(self.run)

    def test_rejects_case_input_changed_after_prediction(self):
        save(self.case / "input.spdx.json", {**self.observation, "name": "changed"})
        with self.assertRaisesRegex(ValueError, "Case input"):
            audited_records(self.run)

    def test_legacy_seal_requires_separate_worker_isolation_evidence(self):
        seal = {
            "spec": self.spec, "prediction_sha256": digest(self.arm / "prediction.spdx.json"),
            "oracle_read_before_seal": False,
        }
        save(self.arm / "seal.json", seal)
        with self.assertRaisesRegex(ValueError, "Missing prediction-worker"):
            audited_records(self.run)
        save(self.arm / "details.json", {"isolation": {"oracle_mounted": False}})
        _, audit = audited_records(self.run)
        declaration = audit["legacy_isolation_declarations"][str(self.arm)]
        self.assertEqual(declaration["seal_worker_flag"], "UNRECORDED_LEGACY_SEAL")
        self.assertFalse(declaration["worker_oracle_mounted"])

    def test_explicit_oracle_exposure_is_rejected_even_for_legacy_inputs(self):
        save(self.arm / "seal.json", {
            "spec": self.spec, "prediction_sha256": digest(self.arm / "prediction.spdx.json"),
            "oracle_read_before_seal": False, "oracle_exposed_to_prediction_worker": True,
        })
        with self.assertRaisesRegex(ValueError, "Missing prediction-worker"):
            audited_records(self.run)

    def test_legacy_diagnostic_schema_can_differ_but_scores_must_match(self):
        older = deepcopy(self.evaluation)
        older.pop("false_positive_metadata")
        save(self.arm / "evaluation.json", older)
        _, audit = audited_records(self.run)
        self.assertIn(str(self.arm), audit["legacy_diagnostic_schema_variants"])
        older["new_metadata"]["f1"] = .5
        save(self.arm / "evaluation.json", older)
        with self.assertRaisesRegex(ValueError, "Evaluation cannot be reproduced"):
            audited_records(self.run)

    def test_rejects_stale_evaluation_and_inconsistent_recorded_scores(self):
        save(self.arm / "evaluation.json", {"different": True})
        with self.assertRaisesRegex(ValueError, "Evaluation cannot be reproduced"):
            audited_records(self.run)
        save(self.arm / "evaluation.json", self.evaluation)
        changed = deepcopy(self.row)
        changed["metrics"]["new_metadata_f1"] = 1.
        save(self.case / "records.json", {"records": [changed]})
        with self.assertRaisesRegex(ValueError, "Recorded F1"):
            audited_records(self.run)


if __name__ == "__main__":
    unittest.main()
