"""Comparator choices remain explicit and distinct from verified reconciliation."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from sbom_recovery.investigation.baseline import baseline
from sbom_recovery.investigation.engine import ingest, export
from tests.test_investigation_engine import document, evidence, make_request


class InvestigationBaselineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def state(self, *documents):
        return ingest(make_request(self.directory.name, list(documents)), self.directory.name)

    def test_union_keeps_version_variants_priority_and_majority_choose(self):
        docs = [document("1.0.0"), document("2.0.0"), document("2.0.0")]
        # Third source must have distinct bytes to be a distinct document vote.
        docs[2]["components"][0]["description"] = "independent generator observation"
        state = self.state(*docs)
        union = baseline(state, "naive_union")
        priority = baseline(state, "fixed_priority")
        majority = baseline(state, "majority")
        self.assertEqual({c["version"] for c in union["components"] if c["name"] == "lib"}, {"1.0.0", "2.0.0"})
        self.assertEqual([c["version"] for c in priority["components"] if c["name"] == "lib"], ["1.0.0"])
        self.assertEqual([c["version"] for c in majority["components"] if c["name"] == "lib"], ["2.0.0"])
        for result in (union, priority, majority):
            self.assertTrue(all(c["status"] == "UNKNOWN" and not c["evidence_ids"] for c in result["components"]))
            self.assertEqual(len(result["raw_observations"]), 6)
            self.assertTrue(result["baseline_choices"])
            self.assertTrue(export(result)["validation-report.json"]["valid"])

    def test_duplicate_bytes_do_not_add_majority_votes(self):
        state = self.state(document("1.0.0"), document("2.0.0"), document("2.0.0"))
        result = baseline(state, "majority")
        self.assertEqual([c["version"] for c in result["components"] if c["name"] == "lib"], ["1.0.0"])

    def test_priority_and_majority_preserve_known_distinct_locators(self):
        state = self.state(document("1.0.0"), document("2.0.0", "node_modules/other/node_modules/lib"))
        for method in ("fixed_priority", "majority"):
            self.assertEqual(len([c for c in baseline(state, method)["components"] if c["name"] == "lib"]), 2)

    def test_union_explicitly_exposes_occurrence_collapse(self):
        state = self.state(document(), document(locator="node_modules/other/node_modules/lib"))
        result = baseline(state, "naive_union")
        libs = [c for c in result["components"] if c["name"] == "lib"]
        self.assertEqual(len(libs), 1)
        self.assertIsNone(libs[0]["locator"])
        self.assertEqual(libs[0]["binding"], "BASELINE_ASSUMPTION")

    def test_single_scanner_uses_only_named_document(self):
        state = self.state(document(), document("2.0.0"))
        result = baseline(state, "single:tool-1")
        self.assertEqual([c["version"] for c in result["components"] if c["name"] == "lib"], ["2.0.0"])
        self.assertEqual(len(result["raw_observations"]), 2)
        self.assertTrue(all(c["status"] == "UNKNOWN" for c in result["components"]))
        with self.assertRaisesRegex(ValueError, "Unknown single"):
            baseline(state, "single:missing")

    def test_lockfile_only_does_not_reuse_scanner_inventory(self):
        state = self.state(document("1.0.0"), document("2.0.0"))
        source = evidence("3.0.0")
        result = baseline(state, "lockfile_only", [source])
        self.assertEqual([c["version"] for c in result["components"] if c["name"] == "lib"], ["3.0.0"])
        self.assertFalse(result["raw_observations"])
        self.assertTrue(all(c["status"] == "SUPPORTED" and not c["observation_ids"] for c in result["components"]))
        build = deepcopy(source)
        build["kind"] = "build_record"
        self.assertFalse(baseline(state, "lockfile_only", [build])["components"])
        self.assertFalse(baseline(state, "lockfile_only")["components"])

    def test_baseline_choices_are_real_correction_decisions(self):
        state = self.state(document("1.0.0"), document("2.0.0"))
        result = baseline(state, "fixed_priority")
        version_change = next(d for d in result["decisions"] if d["field"] == "version")
        self.assertEqual((version_change["before"], version_change["value"]), ("2.0.0", "1.0.0"))
        self.assertEqual(version_change["verification"], "UNVERIFIED_BASELINE_CHOICE")

    def test_unsupported_method_is_rejected(self):
        state = self.state(document(), document("2.0.0"))
        with self.assertRaisesRegex(ValueError, "Unknown investigation"):
            baseline(state, "original_sbom_unifier")


class NativeRootBaselineTests(unittest.TestCase):
    def test_cargo_native_only_preserves_root_without_scanner_observations(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path
        import json
        from sbom_recovery.investigation.demo import create_demo
        from sbom_recovery.investigation.evidence import EvidenceCatalog
        from sbom_recovery.investigation.engine import ingest, export
        from sbom_recovery.investigation.evaluation import score
        from sbom_recovery.reconciliation.merge_contracts_v3 import ReconciliationRequestV3
        with TemporaryDirectory() as temp:
            root = Path(temp) / "demo"
            create_demo(root)
            bundle = root / "cargo"
            request = ReconciliationRequestV3.model_validate_json((bundle / "request.json").read_text())
            source = EvidenceCatalog(request, bundle).acquire("01-resolution")
            result = baseline(ingest(request, bundle), "lockfile_only", [source])
            self.assertEqual(len(result["roots"]), 1)
            self.assertTrue(export(result)["validation-report.json"]["valid"])
            metrics = score(result, json.loads((bundle / "oracle/oracle.json").read_text()))
            self.assertEqual(metrics["paths"]["f1"], 1.0)


if __name__ == "__main__":
    unittest.main()
