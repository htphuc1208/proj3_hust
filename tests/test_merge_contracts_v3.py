"""Multi-SBOM grouping and provenance boundaries, not merge accuracy."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator
from pydantic import ValidationError

from sbom_recovery.core.formats import NativeDocument, validate_native
from sbom_recovery.reconciliation.merge_contracts_v3 import (
    ObservationReferenceV3, ReconciliationRequestV3,
)

ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "research/design/reconciliation-v3"


def request():
    return json.loads((DESIGN / "examples/input.json").read_text())


class MultiSbomContractV3Tests(unittest.TestCase):
    def test_nonartifact_input_is_valid_and_preserves_unknown_features(self):
        data = ReconciliationRequestV3.model_validate(request())
        self.assertIsNone(data.target.artifact)
        self.assertIsNone(data.target.context.features_by_subject["application"])
        self.assertEqual(len(data.documents), 2)

    def test_schema_and_example_match_models_and_native_input_hashes(self):
        schema = json.loads((DESIGN / "schemas/input.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        self.assertEqual({k:v for k,v in schema.items() if k not in {"$id", "$schema"}},
                         ReconciliationRequestV3.model_json_schema())
        raw = request()
        Draft202012Validator(schema).validate(raw)
        self.assertEqual(ReconciliationRequestV3.model_validate(raw).model_dump(mode="json"), raw)
        for item in raw["documents"]:
            path = DESIGN / "examples" / item["document"]["path"]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["document"]["sha256"])
            self.assertTrue(validate_native(json.loads(path.read_text()))["valid"])

    def test_native_refs_are_namespaced_by_document_not_by_ref_text(self):
        raw = request()
        keys = [ObservationReferenceV3(document_sha256=d["document"]["sha256"], native_ref="dependency").key()
                for d in raw["documents"]]
        self.assertNotEqual(keys[0], keys[1])
        versions = []
        for d in raw["documents"]:
            data = json.loads((DESIGN / "examples" / d["document"]["path"]).read_text())
            versions.append(NativeDocument(data).packages()["dependency"]["version"])
        self.assertEqual(versions, ["2.1.0", "2.0.9"])

    def test_single_document_is_not_a_multi_sbom_comparison(self):
        raw = request()
        raw["documents"] = raw["documents"][:1]
        with self.assertRaises(ValidationError):
            ReconciliationRequestV3.model_validate(raw)

    def test_explicitly_different_targets_do_not_share_a_comparison(self):
        raw = request()
        raw["documents"][1]["target_id"] = "other-app"
        with self.assertRaisesRegex(ValidationError, "Different targets"):
            ReconciliationRequestV3.model_validate(raw)

    def test_declared_and_resolved_views_are_not_silently_unified(self):
        raw = request()
        raw["documents"][1]["view"] = "DECLARED"
        with self.assertRaisesRegex(ValidationError, "Different views"):
            ReconciliationRequestV3.model_validate(raw)

    def test_different_contexts_do_not_share_a_comparison(self):
        raw = request()
        raw["documents"][1]["context_id"] = "ctx-windows"
        with self.assertRaisesRegex(ValidationError, "Different contexts"):
            ReconciliationRequestV3.model_validate(raw)

    def test_different_known_revisions_are_rejected(self):
        raw = request()
        raw["documents"][1]["revision_ref"] = "fixture-v2"
        with self.assertRaisesRegex(ValidationError, "Different revisions"):
            ReconciliationRequestV3.model_validate(raw)

    def test_missing_revision_context_and_view_stay_unknown(self):
        raw = request()
        raw["documents"][1].update(revision_ref=None, context_id=None, view="UNKNOWN")
        data = ReconciliationRequestV3.model_validate(raw)
        self.assertIsNone(data.documents[1].revision_ref)
        self.assertIsNone(data.documents[1].context_id)
        self.assertEqual(data.documents[1].view, "UNKNOWN")

    def test_optional_artifact_with_consistent_claim_is_accepted(self):
        raw = request()
        raw["target"]["artifact"] = dict(artifact=dict(path="artifact/app.jar", sha256="a"*64), kind="java_jar")
        raw["documents"][0]["claimed_artifact_sha256"] = "a"*64
        ReconciliationRequestV3.model_validate(raw)
        raw["documents"][0]["claimed_artifact_sha256"] = "f"*64
        with self.assertRaisesRegex(ValidationError, "digest conflicts"):
            ReconciliationRequestV3.model_validate(raw)

    def test_same_producer_name_does_not_collapse_sources(self):
        raw = request()
        raw["documents"][1]["producer"] = deepcopy(raw["documents"][0]["producer"])
        data = ReconciliationRequestV3.model_validate(raw)
        self.assertEqual(len(data.documents), 2)
        self.assertNotEqual(data.documents[0].document.sha256, data.documents[1].document.sha256)

    def test_source_ids_are_unique_across_sboms_and_evidence(self):
        raw = request()
        raw["evidence"] = [dict(source_id=raw["documents"][0]["source_id"],
            blob=dict(path="evidence/metadata.json", sha256="e"*64), kind="registry_metadata")]
        with self.assertRaisesRegex(ValidationError, "unique across"):
            ReconciliationRequestV3.model_validate(raw)

    def test_input_cannot_declare_its_source_verified(self):
        raw = request()
        raw["documents"][0]["verified"] = True
        with self.assertRaisesRegex(ValidationError, "Extra inputs"):
            ReconciliationRequestV3.model_validate(raw)

    def test_consumer_evaluation_declares_configuration_and_snapshot(self):
        raw = request()
        raw["consumer"] = dict(name="design-consumer", version="1", snapshot_kind="RECORDED_RESPONSES",
            configuration=dict(path="consumer/config.json", sha256="c"*64),
            advisory_snapshot=dict(path="consumer/responses.json", sha256="d"*64))
        ReconciliationRequestV3.model_validate(raw)
        del raw["consumer"]["advisory_snapshot"]
        with self.assertRaises(ValidationError):
            ReconciliationRequestV3.model_validate(raw)


if __name__ == "__main__":
    unittest.main()
