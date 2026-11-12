"""End-to-end sealed, process-separated paired investigation experiments."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sbom_recovery.investigation.demo import create_demo
from sbom_recovery.investigation.study import StudyManifest, _read_oracle, _verify_seal, run_study


ROOT = Path(__file__).resolve().parents[1]


class InvestigationStudyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.demo = self.root / "demo"
        create_demo(self.demo)
        self.manifest_path = self.demo / "study.json"
        self.manifest = json.loads(self.manifest_path.read_text())
        self.manifest["bootstrap_samples"] = 25

    def freeze(self):
        self.manifest_path.write_text(json.dumps(self.manifest))

    def test_all_predictions_sealed_before_any_oracle_open_then_scored_per_project(self):
        self.freeze()
        out = self.root / "study"
        reads = []
        def scorer_read(base, blob):
            marker = json.loads((out / "inference-complete.json").read_text())
            self.assertEqual(marker["records"], 10)
            self.assertFalse(marker["oracle_bytes_read"])
            self.assertEqual(len(list((out / "predictions").rglob("seal.json"))), 10)
            for case in self.manifest["cases"]:
                for method in self.manifest["methods"]:
                    self.assertTrue((out / "predictions" / case["case_id"] / "equal_budget" / method / "prediction.json").exists())
            reads.append(blob.path)
            return _read_oracle(base, blob)
        with patch("sbom_recovery.investigation.study._read_oracle", side_effect=scorer_read):
            result = run_study(self.manifest_path, out)
        self.assertEqual(result["counts"], {"SCORED": 10})
        self.assertEqual(len(reads), 2)
        report = json.loads((out / "report.json").read_text())
        self.assertEqual(len(report["per_project"]), 10)
        self.assertTrue(report["paired_comparisons"])
        self.assertTrue(all(r["unit"] == "project" for r in report["paired_comparisons"] if r["projects"]))
        rule = next(r for r in report["records"] if r["case_id"] == "controlled-npm" and r["method"] == "rule")
        self.assertEqual(rule["metrics"]["tool_calls"], 2)
        self.assertGreater(rule["metrics"]["bytes"], 0)
        self.assertEqual(rule["metrics"]["candidate_components_f1"], 1.0)
        self.assertIn("public-advisories.json", rule["public_inputs"])
        self.assertTrue((out / rule["prediction_dir"] / "security-report.json").exists())
        freeze = json.loads((out / "freeze.json").read_text())
        self.assertIn("sbom_recovery/investigation/worker.py", freeze["source_files"])
        self.assertIn("pydantic", freeze["dependencies"])
        self.assertEqual(freeze["manifest_sha256"], hashlib.sha256(self.manifest_path.read_bytes()).hexdigest())

    def test_same_project_or_lineage_cannot_cross_splits(self):
        for field in ("project", "lineage"):
            data = deepcopy(self.manifest)
            data["cases"][1][field] = data["cases"][0][field]
            data["cases"][1]["split"] = "test"
            self.manifest_path.write_text(json.dumps(data))
            with self.subTest(field=field), patch("sbom_recovery.investigation.study._read_oracle") as labels:
                with self.assertRaisesRegex(ValueError, "leakage"):
                    run_study(self.manifest_path, self.root / ("out-" + field))
                labels.assert_not_called()

    def test_duplicates_and_unfrozen_llm_arms_are_rejected(self):
        for kind in ("case", "request", "method", "llm"):
            data = deepcopy(self.manifest)
            if kind == "case":
                data["cases"].append(deepcopy(data["cases"][0]))
            elif kind == "request":
                data["cases"][1]["request"] = deepcopy(data["cases"][0]["request"])
            elif kind == "method":
                data["methods"].append(data["methods"][0])
            else:
                data["methods"].append("agent")
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                StudyManifest.model_validate(data)
        for method in ("single:../../../oracle", "single:/absolute", "single:.."):
            data = deepcopy(self.manifest)
            data["methods"] = [method]
            with self.subTest(method=method), self.assertRaises(ValueError):
                StudyManifest.model_validate(data)

    def test_missing_public_input_keeps_failed_arm_and_never_reads_labels(self):
        self.manifest["cases"] = self.manifest["cases"][:1]
        self.manifest["methods"] = ["observed", "rule"]
        self.freeze()
        (self.demo / "npm/inputs/tool-0.cdx.json").unlink()
        with patch("sbom_recovery.investigation.study._read_oracle") as labels:
            result = run_study(self.manifest_path, self.root / "failed")
            self.assertEqual(result["counts"], {"FAILED": 2})
            labels.assert_not_called()

    def test_equal_information_gives_arms_the_same_acquired_facts(self):
        self.manifest["cases"] = self.manifest["cases"][:1]
        self.manifest["methods"] = ["deterministic", "rule"]
        self.manifest["conditions"] = ["equal_information"]
        self.manifest["budget"] = {"max_tool_calls": 0}
        self.freeze()
        out = self.root / "equal-info"
        result = run_study(self.manifest_path, out)
        self.assertEqual(result["counts"], {"SCORED": 2})
        folders = [out / "predictions/controlled-npm/equal_information" / method for method in self.manifest["methods"]]
        evidence = [json.loads((folder / "acquired-evidence.json").read_text()) for folder in folders]
        self.assertEqual(evidence[0], evidence[1])
        self.assertEqual(len(evidence[0]), 2)
        for folder in folders:
            pred = json.loads((folder / "prediction.json").read_text())
            self.assertEqual(pred["investigation"]["usage"]["tool_calls"], 0)
            self.assertFalse(pred["investigation"]["precollection"]["charged_to_arm"])

    def test_original_unifier_on_cyclonedx_is_explicitly_unsupported(self):
        self.manifest["cases"] = self.manifest["cases"][:1]
        self.manifest["methods"] = ["sbom_unifier"]
        self.freeze()
        with patch("sbom_recovery.investigation.study._read_oracle") as labels:
            result = run_study(self.manifest_path, self.root / "unsupported")
            self.assertEqual(result["counts"], {"UNSUPPORTED": 1})
            labels.assert_not_called()

    def test_prediction_and_seal_tampering_are_detected_before_scoring(self):
        folder = self.root / "sealed"
        folder.mkdir()
        (folder / "prediction.json").write_text("{}")
        seal = {"schema_version": "investigation-seal-v1", "files": {"prediction.json": hashlib.sha256(b"{}").hexdigest()}}
        raw = json.dumps(seal).encode()
        (folder / "seal.json").write_bytes(raw)
        seal_hash = hashlib.sha256(raw).hexdigest()
        self.assertEqual(_verify_seal(folder, seal_hash), {})
        (folder / "prediction.json").write_text('{"changed":true}')
        with self.assertRaisesRegex(ValueError, "digest"):
            _verify_seal(folder, seal_hash)
        (folder / "seal.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "seal changed"):
            _verify_seal(folder, seal_hash)

    def test_audit_rejects_oracle_reads_and_child_execution(self):
        public = self.root / "public"
        output = self.root / "predictions"
        public.mkdir()
        output.mkdir()
        forbidden = self.root / "oracle.json"
        forbidden.write_text('{"secret":true}')
        script = """
from pathlib import Path
import subprocess
from sbom_recovery.investigation.worker import install_read_boundary
install_read_boundary(Path(__import__('sys').argv[1]),Path(__import__('sys').argv[2]))
for action in (lambda: Path(__import__('sys').argv[3]).read_text(),lambda: subprocess.run(['/bin/true'])):
    try:
        action()
    except PermissionError:
        print('DENIED')
    else:
        raise RuntimeError('boundary failed')
"""
        process = subprocess.run([sys.executable, "-B", "-c", script, str(public), str(output), str(forbidden)],
            cwd=ROOT, capture_output=True, text=True, check=True)
        self.assertEqual(process.stdout.splitlines(), ["DENIED", "DENIED"])


if __name__ == "__main__":
    unittest.main()
