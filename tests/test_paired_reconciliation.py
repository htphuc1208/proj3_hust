"""Synthetic safety/integrity controls; empirical claims require the real run."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from research_core import load
from sbom_recovery.formats import NativeDocument
from sbom_recovery.paired_reconciliation import METHODS, native_changes, predict
from sbom_recovery.reconciliation_comparison import paired_metrics, stage_changes, verify_predictions
from sbom_recovery.storage import save
from sbom_recovery.targets import metadata_inventory
from tests.test_agent_recovery import context, document


class PairedReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "target"
        self.doc = document()
        self.doc["components"].append({"type": "library", "name": "gamma", "version": "3", "purl": "pkg:pypi/gamma@3", "bom-ref": "c"})
        self.doc["dependencies"] = [{"ref": "b", "dependsOn": ["c"]}]
        self.put("alpha", "1", "Requires-Dist: beta>=2\n")
        self.put("beta", "2", 'Requires-Dist: gamma; extra == "optional"\n')
        self.put("gamma", "3", "")

    def put(self, name, version, requires):
        path = self.target / "lib/python3.11/site-packages" / f"{name}-{version}.dist-info/METADATA"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n{requires}\n")

    def execute(self, name="worker"):
        self.ctx = context().model_copy(update={"target_id": metadata_inventory(self.target)[1]})
        out = self.root / name
        result = predict(self.doc, self.ctx, self.target, "2026-10-28T00:00:00Z", out)
        return out, result

    def test_addition_and_retraction_are_separate_under_identical_evidence(self):
        original = deepcopy(self.doc)
        out, result = self.execute()
        predictions, details = verify_predictions(out, self.doc, self.ctx.model_dump())
        self.assertEqual(set(result["methods"]), set(METHODS))
        self.assertEqual(self.doc, original)
        self.assertEqual(NativeDocument(predictions["observed"]).edges(), {("b", "c")})
        self.assertEqual(NativeDocument(predictions["additive"]).edges(), {("a", "b"), ("b", "c")})
        self.assertEqual(NativeDocument(predictions["additive_reconciliation"]).edges(), {("a", "b")})
        self.assertEqual(len({d["evidence_manifest_sha256"] for d in details.values()}), 1)
        self.assertGreaterEqual(details["additive_reconciliation"]["duration_seconds"], details["additive"]["duration_seconds"])

    def test_known_transitive_extras_prevent_wrong_retraction(self):
        self.put("alpha", "1", "Requires-Dist: beta[optional]>=2\n")
        out, _ = self.execute()
        docs, _ = verify_predictions(out, self.doc, self.ctx.model_dump())
        self.assertIn(("b", "c"), NativeDocument(docs["additive_reconciliation"]).edges())

    def test_unknown_transitive_extras_prevent_retraction(self):
        self.put("alpha", "1", 'Requires-Dist: beta[optional]; implementation_name == "pypy"\n')
        out, _ = self.execute()
        docs, details = verify_predictions(out, self.doc, self.ctx.model_dump())
        self.assertIn(("b", "c"), NativeDocument(docs["additive_reconciliation"]).edges())
        self.assertEqual(details["additive_reconciliation"]["assessment"]["counts"].get("UNKNOWN"), 1)

    def test_explicit_empty_source_is_retained_by_existing_additive_policy(self):
        self.doc["dependencies"].append({"ref": "a", "dependsOn": []})
        out, _ = self.execute()
        docs, details = verify_predictions(out, self.doc, self.ctx.model_dump())
        self.assertNotIn(("a", "b"), NativeDocument(docs["additive"]).edges())
        supported = details["additive"]["verified"]["supported"]
        self.assertTrue(any(r["reason"] == "CONTRADICTED_DECLARATION" for r in supported))

    def test_policy_failure_remains_visible_with_fallback(self):
        with patch("sbom_recovery.paired_reconciliation.deterministic_policy", side_effect=ValueError("fixture")):
            out, result = self.execute()
        docs, details = verify_predictions(out, self.doc, self.ctx.model_dump())
        self.assertEqual(docs["additive"], self.doc)
        self.assertEqual(result["methods"]["additive"], "POLICY_ERROR")
        self.assertEqual(details["additive_reconciliation"]["status"], "POLICY_ERROR")

    def test_tampered_input_prediction_details_context_and_blob_are_rejected(self):
        for index, kind in enumerate(("input", "prediction", "details", "context", "blob", "pair")):
            with self.subTest(kind=kind):
                out, _ = self.execute("worker-" + str(index))
                observation, ctx = deepcopy(self.doc), self.ctx.model_dump()
                if kind == "input":
                    observation["version"] = 9
                elif kind == "context":
                    ctx["active_extras"] = ["optional"]
                elif kind == "blob":
                    next((out / "evidence/blobs").iterdir()).write_bytes(b"changed")
                else:
                    file = {"prediction": "additive/prediction.json", "details": "additive/details.json", "pair": "additive/seal.json"}[kind]
                    value = load(out / file)
                    value["tampered"] = True
                    save(out / file, value)
                with self.assertRaisesRegex(ValueError, "mismatch|changed"):
                    verify_predictions(out, observation, ctx)

    def test_native_edge_changes_are_distinct_from_identity_changes(self):
        after = deepcopy(self.doc)
        after["components"][1]["purl"] = "pkg:pypi/gamma@4"
        result = native_changes(self.doc, after)
        self.assertFalse(result["added_native_edges"])
        self.assertFalse(result["removed_native_edges"])
        self.assertEqual(len(result["changed_identity_refs"]), 1)
        facts = stage_changes(self.doc, after, self.doc)
        self.assertEqual(facts["removed"][0]["label"], "KNOWN_TRUE")
        self.assertEqual(facts["added"][0]["label"], "KNOWN_FALSE")

    def test_unresolved_reference_parent_is_not_a_known_negative(self):
        reference = deepcopy(self.doc)
        reference["dependencies"] = []
        result = stage_changes(self.doc, reference, reference, {"pkg:pypi/beta@2"})
        self.assertEqual(result["removed"][0]["label"], "UNKNOWN")

    def test_undefined_scores_use_common_metric_specific_denominators(self):
        def row(name, edge_count, values):
            return {"project": name, "reference_edges": edge_count,
                    "arms": {m: {"whole_edges": values[m]} for m in METHODS}}
        numeric = {"precision": .5, "recall": 1., "f1": 2/3}
        undefined = {"precision": None, "recall": None, "f1": None}
        rows = [row("positive", 1, {m: numeric for m in METHODS}),
                row("empty", 0, {m: undefined if m == "additive_reconciliation" else numeric for m in METHODS})]
        result = paired_metrics(rows)
        self.assertEqual(result["metrics"]["precision"]["eligible_projects"], 1)
        self.assertEqual(result["metrics"]["precision"]["means"]["observed"], .5)
        self.assertEqual(paired_metrics(rows, True)["population_projects"], 1)


if __name__ == "__main__":
    unittest.main()
