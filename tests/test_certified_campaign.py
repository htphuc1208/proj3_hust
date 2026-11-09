"""Seal/withholding/scoring controls for the V2 development campaign."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from sbom_recovery.core.formats import sha
from sbom_recovery.campaign.targets import metadata_inventory
from sbom_recovery.reconciliation.certified_analysis import score_changes, summarize, verify_matrix
from sbom_recovery.reconciliation.certified_worker import METHODS
from sbom_recovery.reconciliation.certified_worker import predict
from sbom_recovery.reconciliation.contracts_v2 import ContextKnowledgeV2
from sbom_recovery.reconciliation.certified_evidence import collect_evidence
from tests.test_agent_recovery import context as legacy_context
from tests.test_certified_reconciliation import INSTALLATION

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("certified_development_runner", ROOT / "scripts/run_certified_development.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CertifiedCampaignTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capture = self.root / "capture"
        self.target = self.capture / "runtime/target"
        self.document = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                         "components": [], "dependencies": [{"ref": "alpha", "dependsOn": ["beta"]}]}
        for name in ("alpha", "beta", "gamma", "delta"):
            relative = f"{INSTALLATION}/{name}-1.dist-info/METADATA"
            path = self.target / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"Metadata-Version: 2.3\nName: {name}\nVersion: 1\n\n")
            self.document["components"].append({"type": "library", "bom-ref": name, "name": name,
                "version": "1", "purl": f"pkg:pypi/{name}@1",
                "properties": [{"name": "sbom-recovery:metadata-path", "value": relative}]})
        self.legacy = legacy_context().model_copy(update={"target_id": metadata_inventory(self.target)[1],
            "evidence_cutoff": "2026-11-09T00:00:00Z"})
        self.save(self.capture / "context.json", self.legacy.model_dump())
        self.save(self.capture / "capture.json", {"completed_at": "2026-11-09T00:00:00Z"})
        self.save(self.capture / "runtime/syft.spdx.json", self.document)

    def save(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def test_partial_staging_removes_withheld_bytes(self):
        job = self.root / "partial"
        record = runner.stage_case(self.capture, {"name": "alpha", "version": "1"}, "partial_metadata", job)
        manifest = json.loads((job / "evidence/manifest.json").read_text())
        self.assertEqual(len(record["withheld_sources"]), 2)
        for source in manifest["sources"]:
            self.assertEqual((job / "evidence" / source["path"]).exists(), source["acquired"])
        self.assertFalse((job / "oracle").exists())

    def test_unknown_context_staging_omits_hidden_legacy_context(self):
        job = self.root / "unknown"
        runner.stage_case(self.capture, {"name": "alpha", "version": "1"}, "unknown_context", job)
        self.assertFalse((job / "legacy-context.json").exists())
        context = json.loads((job / "context.json").read_text())
        self.assertEqual(context["marker_values"], {})
        self.assertFalse(context["root_requests_complete"])

    def test_worker_predictions_are_sealed_and_tamper_detected(self):
        job = self.root / "full"
        runner.stage_case(self.capture, {"name": "alpha", "version": "1"}, "full_metadata", job)
        output = self.root / "predictions"
        result = predict(job, output)
        self.assertEqual(result["status"], "SEALED")
        predictions = verify_matrix(job, output)
        self.assertEqual(predictions["certified_v2"][1]["status"], "COMPLETE")
        path = output / "certified_v2/prediction.json"
        document = json.loads(path.read_text())
        document["version"] += 1
        self.save(path, document)
        with self.assertRaises(ValueError):
            verify_matrix(job, output)

    def test_v1_adapter_does_not_inherit_v2_metadata_version_restriction(self):
        path = self.target / INSTALLATION / "alpha-1.dist-info/METADATA"
        path.write_text('Metadata-Version: 2.0\nName: alpha\nVersion: 1\nRequires-Dist: beta; extra == "opt"\n\n')
        self.legacy = self.legacy.model_copy(update={"target_id": metadata_inventory(self.target)[1]})
        self.save(self.capture / "context.json", self.legacy.model_dump())
        job = self.root / "v1-adapter"
        runner.stage_case(self.capture, {"name": "alpha", "version": "1"}, "full_metadata", job)
        output = self.root / "v1-predictions"
        predict(job, output)
        predictions = verify_matrix(job, output)
        from sbom_recovery.core.formats import NativeDocument
        self.assertFalse(NativeDocument(predictions["legacy_reconciliation"][0]).edges())
        self.assertEqual(NativeDocument(predictions["certified_v2"][0]).edges(), {("alpha", "beta")})

    def test_unknown_labels_do_not_become_known_errors_or_successes(self):
        predicted = deepcopy(self.document)
        predicted["dependencies"] = []
        reference = deepcopy(predicted)
        score = score_changes(self.document, predicted, reference, {"pkg:pypi/alpha@1"})
        self.assertEqual(score["known_changes"], 0)
        self.assertEqual(score["unknown_changes"], 1)
        self.assertIsNone(score["selective_risk"])
        self.assertEqual(score["optimistic_risk"], 0)
        self.assertEqual(score["pessimistic_risk"], 1)
        score = score_changes(self.document, predicted, reference)
        self.assertEqual(score["known_changes"], 1)
        self.assertEqual(score["incorrect_changes"], 0)

    def test_duplicate_coordinates_have_unknown_instance_change_labels(self):
        self.document["components"].append({**self.document["components"][0], "bom-ref": "alpha-copy"})
        predicted = deepcopy(self.document)
        predicted["dependencies"] = []
        self.assertEqual(score_changes(self.document, predicted, predicted)["unknown_changes"], 1)

    def test_empty_and_failed_runs_do_not_pass_research_gate(self):
        summary = summarize([], [{"case": "failed"}])
        self.assertEqual(summary["empirical_advantage_gate"], "UNMEASURED_INCOMPLETE_RUN")
        self.assertEqual(summary["human_review_completed"], 0)
        self.assertEqual(summary["heldout_projects_used"], 0)

    def test_panel_eligibility_excludes_artificial_reference_root_edge(self):
        job = self.root / "alpha/full_metadata/input"
        runner.stage_case(self.capture, {"name": "alpha", "version": "1"}, "full_metadata", job)
        output = job.parent / "output/predictions"
        output.parent.mkdir()
        predict(job, output)
        oracle = self.capture / "oracle"
        self.save(oracle / "pip_inspect.json", {})
        self.save(oracle / "install_report.json", {})
        self.save(oracle / "installed_reference_provenance.json", {
            "pip_inspect_sha256": runner.digest(oracle / "pip_inspect.json"),
            "installation_report_sha256": runner.digest(oracle / "install_report.json")})
        reference = deepcopy(self.document)
        reference["metadata"] = {"component": {"type": "application", "name": "synthetic", "bom-ref": "root"}}
        reference["dependencies"] = [{"ref": "root", "dependsOn": ["alpha"]}]
        self.save(oracle / "installed_reference.cdx.json", reference)
        self.save(oracle / "installed_reference.json", {"nodes": [], "unresolved": []})
        expected = {"alpha": {"reference_sha256": runner.digest(oracle / "installed_reference.cdx.json")}}
        captures = self.root / "captures"
        (captures / "alpha").mkdir(parents=True)
        shutil.copytree(oracle, captures / "alpha/oracle")
        # The scorer's graph excludes the unversioned artificial root. Physical
        # native edge counting would incorrectly declare this reference nonempty.
        records = runner.score_sealed_cases([job.parent], captures, expected)
        self.assertEqual(records[0]["reference_edges"], 0)
        summary = summarize(records, [])
        self.assertEqual(summary["common_f1_panels"]["full_metadata"]["common_nonempty_reference_projects"], 0)


if __name__ == "__main__":
    unittest.main()
