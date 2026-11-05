"""Scientific audit contracts. Synthetic controls verify integrity, not quality."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from research_core import digest
from sbom_recovery.contracts import TargetContext
from sbom_recovery.formats import sha
from sbom_recovery.storage import save
from scripts.audit_raw_sbom_study import (
    additive_bound, audit_arm, edge_context, error_class, matrix_progress, metadata_catalog,
    summarize_edge_errors, verify_manifest_binding,
)
from scripts.export_interim_sbom_report import METHODS
from tests import test_interim_report as interim_fixture


class ContextAttributionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.capture = Path(self.temp.name)
        self.context = TargetContext(
            os_name="posix", sys_platform="linux", platform_machine="x86_64",
            python_version="3.11", python_full_version="3.11.16", platform_system="Linux",
            active_extras=[], target_id="fixture", evidence_cutoff="2026-10-28T00:00:00Z",
            root_purls=["pkg:pypi/parent@1"],
        )
        self.binding = {"sources": {}}
        self.add_metadata("parent", 'Requires-Dist: child; extra == "optional"\n')
        self.add_metadata("child", "")

    def add_metadata(self, name, requirements):
        relative = f"lib/python3.11/site-packages/{name}-1.dist-info/METADATA"
        path = self.capture / "runtime/target" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = f"Metadata-Version: 2.3\nName: {name}\nVersion: 1\n{requirements}\n".encode()
        path.write_bytes(raw)
        self.binding["sources"][name] = {
            "kind": "target_metadata", "description": "target:" + relative,
            "content_binding": sha({"raw_hex": raw.hex()}), "available_at": "2026-10-27T00:00:00Z",
        }
        return path

    def inspect(self, context=None):
        context = context or self.context
        catalog, info = metadata_catalog(self.capture, self.binding, context)
        return edge_context(("pkg:pypi/parent@1", "pkg:pypi/child@1"), catalog, info, context)

    def test_inactive_extra_is_evidence_supported_category_c(self):
        result = self.inspect()
        self.assertEqual(result["category"], "C")
        self.assertFalse(result["matching_requirements"][0]["active"])
        self.assertIsNotNone(result["parent_metadata_sha256"])

    def test_active_extra_does_not_support_category_c(self):
        result = self.inspect(self.context.model_copy(update={"active_extras": ["optional"]}))
        self.assertEqual(result["category"], "UNRESOLVED")
        self.assertTrue(result["matching_requirements"][0]["active"])

    def test_transitive_extra_comes_from_allowed_metadata_not_oracle(self):
        self.add_metadata("root", 'Requires-Dist: parent[optional]\n')
        context = self.context.model_copy(update={"root_purls": ["pkg:pypi/root@1"]})
        # An oracle file is deliberately malformed: attribution must never open it.
        (self.capture / "oracle").mkdir()
        (self.capture / "oracle/installed_reference.json").write_text("not JSON")
        result = self.inspect(context)
        self.assertEqual(result["effective_extras"], ["optional"])
        self.assertEqual(result["category"], "UNRESOLVED")

    def test_unknown_marker_is_not_evaluated_on_the_audit_host(self):
        self.add_metadata("parent", 'Requires-Dist: child; platform_python_implementation == "CPython"\n')
        result = self.inspect()
        self.assertEqual(result["category"], "UNRESOLVED")
        self.assertIsNone(result["matching_requirements"][0]["active"])

    def test_unknown_transitive_marker_cannot_prove_an_extra_inactive(self):
        self.add_metadata("root", 'Requires-Dist: parent[optional]; platform_python_implementation == "CPython"\n')
        result = self.inspect(self.context.model_copy(update={"root_purls": ["pkg:pypi/root@1"]}))
        self.assertEqual(result["effective_extras"], [])
        self.assertEqual(result["possible_extras"], ["optional"])
        self.assertEqual(result["category"], "UNRESOLVED")

    def test_one_active_declaration_prevents_inactive_attribution(self):
        self.add_metadata("parent", 'Requires-Dist: child; extra == "optional"\nRequires-Dist: child\n')
        self.assertEqual(self.inspect()["category"], "UNRESOLVED")

    def test_incomplete_or_future_metadata_prevents_context_attribution(self):
        self.add_metadata("broken", "Requires-Dist: !!!\n")
        self.assertEqual(self.inspect()["category"], "UNRESOLVED")
        self.binding["sources"].pop("broken")
        self.binding["sources"]["child"]["available_at"] = "2026-10-29T00:00:00Z"
        self.assertEqual(self.inspect()["category"], "UNRESOLVED")

    def test_changed_evidence_and_path_escape_fail_closed(self):
        path = self.add_metadata("child", "")
        path.write_text("changed")
        with self.assertRaisesRegex(ValueError, "metadata changed"):
            self.inspect()
        self.add_metadata("child", "")
        self.binding["sources"]["child"]["description"] = "target:../../outside"
        with self.assertRaisesRegex(ValueError, "escapes target"):
            self.inspect()


class RawMatrixTests(unittest.TestCase):
    def setUp(self):
        # Reuse the actual seven-method seal fixture, without treating it as data.
        self.fixture = interim_fixture.InterimSnapshotTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.study = self.fixture.study
        cohort = self.fixture.root / "cohort.json"
        save(cohort, {"projects": [{"name": "example", "partition": "test"}]})
        save(self.study / "plan.json", {"cohort": str(cohort), "cohort_sha256": digest(cohort),
            "stages": [{"name": "test/raw", "expected_cases": 3, "methods": list(METHODS),
                "conditions": ["fixed"], "budgets": [64], "repetitions": 3, "seeds": [11]}]})

    def test_case_count_is_not_a_complete_matrix(self):
        progress, _, _ = matrix_progress(self.study)
        self.assertFalse(progress["complete"])
        self.assertEqual(progress["missing"], 2)

    def test_full_matrix_accepts_terminal_errors(self):
        for repetition in [1, 2]:
            rows = deepcopy(self.fixture.rows)
            for r in rows:
                r["repetition"] = repetition
            case = self.study / f"test/raw/example/fixed/raw-0-11/budget-64/rep-{repetition}"
            save(case / "records.json", {"records": rows})
            for method in METHODS:
                save(case / method / "evaluation.json", {})
        progress, _, _ = matrix_progress(self.study)
        self.assertTrue(progress["complete"])

    def test_duplicate_case_and_unexpected_repetition_are_rejected(self):
        extra = self.study / "test/raw/extra/records.json"
        save(extra, {"records": self.fixture.rows})
        with self.assertRaisesRegex(ValueError, "duplicate raw case"):
            matrix_progress(self.study)

    def test_unscored_arm_is_not_completion(self):
        (self.fixture.case / "single_agent/evaluation.json").unlink()
        progress, _, _ = matrix_progress(self.study)
        self.assertEqual(len(progress["unscored"]), 1)
        self.assertFalse(progress["complete"])

    def test_context_or_evaluation_drift_rejected_by_rescoring(self):
        context = TargetContext(os_name="posix", sys_platform="linux", platform_machine="x86_64",
            python_version="3.11", python_full_version="3.11.16", platform_system="Linux",
            active_extras=[], target_id="fixture", evidence_cutoff="2026-10-28T00:00:00Z")
        row = deepcopy(self.fixture.rows[0])
        with self.assertRaisesRegex(ValueError, "context differs"):
            audit_arm(self.fixture.root, self.fixture.case, row, context)
        row["context_sha256"] = sha(context.model_dump())
        with patch("scripts.audit_raw_sbom_study.score_after_seal", return_value={"changed": True}):
            with self.assertRaisesRegex(ValueError, "independent re-scoring"):
                audit_arm(self.fixture.root, self.fixture.case, row, context)


class DiagnosticUnitsTests(unittest.TestCase):
    def test_oracle_bound_is_conditional_on_preserving_edge_identities(self):
        doc = {"spdxVersion": "SPDX-2.3", "packages": []}
        observed = {"whole_edges": {"tp": 0, "fp": 2, "fn": 1}}
        predicted = {"whole_edges": {"f1": .5}}
        result = additive_bound(observed, predicted, doc, doc)
        self.assertEqual(result["bound_f1"], .5)
        self.assertTrue(result["at_bound"])
        empty = {"whole_edges": {"tp": 0, "fp": 0, "fn": 0}}
        self.assertIsNone(additive_bound(empty, {"whole_edges": {"f1": None}}, doc, doc)["bound_f1"])

    def test_changed_acquisition_manifest_is_rejected(self):
        identity = {"kind": "target_metadata", "sha256": "fixture-hash"}
        manifest = {"records": [{**identity, "evidence_id": sha(identity), "acquired_at": "2026-10-28T00:00:00Z"}]}
        details = {"isolation": {"final_evidence_sha256": sha(manifest)}}
        verify_manifest_binding(manifest, details)
        manifest["records"][0]["sha256"] = "changed"
        with self.assertRaisesRegex(ValueError, "worker binding"):
            verify_manifest_binding(manifest, details)
        details["isolation"]["final_evidence_sha256"] = sha(manifest)
        with self.assertRaisesRegex(ValueError, "identity digest"):
            verify_manifest_binding(manifest, details)

    def test_repeated_errors_are_not_new_project_edge_facts(self):
        item = {"condition": "fixed", "method": "deterministic", "direction": "FP", "project": "fixture",
                "source_purl": "a", "target_purl": "b", "origin": "INHERITED_FROM_OBSERVATION",
                "category": "C", "attribution": "inactive"}
        group = summarize_edge_errors([item, item, item])[0]
        self.assertEqual(group["error_occurrences"], 3)
        self.assertEqual(group["distinct_project_edges"], 1)

    def test_terminal_symptoms_are_bounded_and_unknown_stays_unknown(self):
        self.assertEqual(error_class("Gateway read timeout"), "TIMEOUT")
        self.assertEqual(error_class("Connection failed secret=not-for-report"), "CONNECTION")
        self.assertEqual(error_class("truncated response"), "TRUNCATED_RESPONSE")
        self.assertEqual(error_class(""), "UNRECORDED")


if __name__ == "__main__":
    unittest.main()
