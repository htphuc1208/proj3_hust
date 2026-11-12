"""Semantic boundaries for draft artifact contracts, not reconstruction accuracy."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator
from pydantic import ValidationError

from sbom_recovery.reconciliation.contracts_v3 import (
    ArtifactAssessmentV3, ArtifactRequestV3, ClaimAssessmentV3, ContextKnowledgeV3,
)

ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "research/design/artifact-reconciliation-v3"


def example(name="supported-component"):
    return json.loads((DESIGN / "examples" / (name + ".assessment.json")).read_text())


class ArtifactContractV3Tests(unittest.TestCase):
    def rejected(self, data, message):
        with self.assertRaisesRegex(ValidationError, message):
            ArtifactAssessmentV3.model_validate(data)

    def test_exported_schemas_are_current_and_all_examples_round_trip(self):
        for kind, model in [("input", ArtifactRequestV3), ("assessment", ArtifactAssessmentV3)]:
            schema = json.loads((DESIGN / "schemas" / (kind + ".schema.json")).read_text())
            Draft202012Validator.check_schema(schema)
            fresh = model.model_json_schema()
            self.assertEqual({k:v for k,v in schema.items() if k not in {"$schema", "$id"}}, fresh)
            files = [DESIGN / "examples/input.json"] if kind == "input" else sorted((DESIGN / "examples").glob("*.assessment.json"))
            for path in files:
                with self.subTest(path=path.name):
                    data = json.loads(path.read_text())
                    Draft202012Validator(schema).validate(data)
                    self.assertEqual(model.model_validate(data).model_dump(mode="json"), data)

    def test_unknown_features_are_distinct_from_known_empty(self):
        context = ContextKnowledgeV3(context_id="c", features_by_subject={"known":[], "unknown":None})
        self.assertEqual(context.features_by_subject["known"], [])
        self.assertIsNone(context.features_by_subject["unknown"])

    def test_input_source_cannot_grant_itself_a_binding(self):
        data = json.loads((DESIGN / "examples/input.json").read_text())
        data["evidence"] = [{"source_id":"e", "kind":"artifact_bytes", "blob":data["target"]["artifact"],
                             "binding":"DIRECT_ARTIFACT"}]
        with self.assertRaisesRegex(ValidationError, "Extra inputs"):
            ArtifactRequestV3.model_validate(data)

    def test_artifact_name_does_not_override_mismatched_digest(self):
        data = example()
        data["evidence"][0]["observed_target_sha256"] = "f" * 64
        self.rejected(data, "different target")

    def test_fact_of_another_target_is_rejected(self):
        data = example()
        data["claims"][0]["scope"]["target_sha256"] = "f" * 64
        self.rejected(data, "another artifact")

    def test_resolved_context_cannot_be_implicitly_selected(self):
        data = example("metadata-only")
        data["claims"][-1]["scope"]["context_id"] = None
        self.rejected(data, "explicit context ID")

    def test_evidence_for_another_context_cannot_authorize_current_claim(self):
        data = example("metadata-only")
        data["claims"][-1]["scope"]["context_id"] = "ctx-other"
        self.rejected(data, "another context")

    def test_registry_alone_cannot_confirm_artifact_presence(self):
        data = example()
        source = deepcopy(data["evidence"][0])
        source.update(source_id="registry", kind="registry_metadata", binding="UNBOUND", observed_target_sha256=None)
        data["evidence"].append(source)
        data["claims"][1]["support_evidence_ids"] = ["registry"]
        self.rejected(data, "Each polarity")

    def test_registry_negative_cannot_create_conflict_against_artifact_evidence(self):
        data = example("conflicting-identity")
        source = next(e for e in data["evidence"] if e["source_id"] == "source:second-observation")
        source.update(kind="registry_metadata", binding="UNBOUND", observed_target_sha256=None)
        self.rejected(data, "Each polarity")

    def test_unknown_claim_cannot_authorize_change(self):
        data = example("ambiguous-identity")
        data["changes"][0]["disposition"] = "APPLY"
        self.rejected(data, "Unknown/conflicting")

    def test_conflict_cannot_be_resolved_by_automatic_change(self):
        data = example("conflicting-identity")
        data["changes"][0]["disposition"] = "APPLY"
        self.rejected(data, "Unknown/conflicting")

    def test_lone_partial_fingerprint_candidate_does_not_become_unique(self):
        data = example()
        data["bindings"][0]["basis"] = "PARTIAL_FINGERPRINT"
        self.rejected(data, "affirmative binding evidence")

    def test_ambiguous_occurrence_cannot_authorize_change_even_if_claim_is_supported(self):
        data = example()
        second = deepcopy(data["candidates"][0])
        second.update(candidate_id="other", version="2.0", purl="pkg:maven/org.example/text@2.0")
        data["candidates"].append(second)
        data["bindings"][0].update(candidate_ids=["identity:text:1.9", "other"], resolution="AMBIGUOUS")
        self.rejected(data, "uniquely bound")

    def test_change_cannot_borrow_identity_from_another_occurrence(self):
        data = example()
        data["changes"][0]["subject"] = "occ:unrelated"
        self.rejected(data, "subject is not bound")

    def test_missing_candidate_reference_is_rejected(self):
        data = example()
        data["claims"][0]["object"] = "identity:missing"
        self.rejected(data, "unknown candidate")

    def test_component_addition_needs_presence_of_the_same_occurrence(self):
        data = example()
        data["claims"][1]["subject"] = "occ:another"
        self.rejected(data, "this target occurrence")

    def test_no_detection_without_closed_scope_cannot_refute_presence(self):
        data = example("metadata-only")
        data["claims"][2]["refutation_coverage_ids"] = []
        self.rejected(data, "closure coverage")

    def test_partial_coverage_cannot_refute_presence(self):
        data = example("metadata-only")
        data["coverage"][0]["status"] = "PARTIAL"
        self.rejected(data, "completely cover")

    def test_archive_entries_do_not_close_semantic_class_identity_domain(self):
        data = example("metadata-only")
        data["coverage"][0]["scope"]["unit_domain"] = "literal_archive_entry"
        self.rejected(data, "exact scope")

    def test_complete_enumeration_with_unknown_mapping_cannot_refute_code_identity(self):
        data = example("metadata-only")
        data["coverage"][0]["identity_mapping_complete"] = False
        self.rejected(data, "semantic identity")

    def test_literal_path_absence_needs_no_claim_of_complete_identity_mapping(self):
        data = example("metadata-only")
        data["claims"][2]["predicate"] = "unit_present"
        data["claims"][2]["subject"] = "entry:SomeClass.class"
        data["claims"][2]["scope"]["unit_domain"] = "literal_archive_entry"
        data["coverage"][0]["scope"]["unit_domain"] = "literal_archive_entry"
        data["coverage"][0]["identity_mapping_complete"] = False
        ArtifactAssessmentV3.model_validate(data)

    def test_selected_dependency_and_absent_code_can_both_be_true_without_conflict(self):
        data = ArtifactAssessmentV3.model_validate(example("metadata-only"))
        statuses = {c.predicate:c.status for c in data.claims}
        self.assertEqual(statuses["selected"], "SUPPORTED")
        self.assertEqual(statuses["code_present"], "REFUTED")
        self.assertFalse(data.changes)
        self.assertEqual(data.runtime_exploitability, "NOT_ASSESSED")

    def edge_data(self, predicate="direct_dependency"):
        data = example("metadata-only")
        root = deepcopy(data["candidates"][0])
        root.update(candidate_id="identity:root", name="app", version="1", purl="pkg:maven/org.example/app@1")
        data["candidates"].append(root)
        binding = deepcopy(data["bindings"][0])
        binding.update(binding_id="binding:root", occurrence_id="occ:root", candidate_ids=["identity:root"])
        data["bindings"].append(binding)
        claim = deepcopy(data["claims"][-1])
        claim.update(claim_id="claim:edge", subject="occ:root", predicate=predicate, object="occ:text")
        data["claims"].append(claim)
        data["changes"] = [dict(change_id="change:edge", operation="ADD_DIRECT_DEPENDENCY", disposition="APPLY",
            scope=claim["scope"], subject="occ:root", related_occurrence_id="occ:text", claim_ids=[claim["claim_id"]],
            binding_ids=["binding:root", "binding:text"], rule_id="test.native-edge", reason="Matched native dependency tree")]
        return data

    def test_supported_direct_dependency_requires_two_distinct_bound_endpoints(self):
        ArtifactAssessmentV3.model_validate(self.edge_data())
        data = self.edge_data()
        data["changes"][0]["binding_ids"] = ["binding:root"]
        self.rejected(data, "distinct occurrences")

    def test_containment_cannot_authorize_dependency_edge(self):
        data = self.edge_data()
        claim = data["claims"][-1]
        claim.update(predicate="contains", scope=deepcopy(data["bindings"][0]["scope"]))
        self.rejected(data, "Only a direct-dependency claim")

    def test_edge_of_other_endpoints_cannot_authorize_change(self):
        data = self.edge_data()
        data["claims"][-1]["object"] = "occ:other"
        self.rejected(data, "these endpoints")

    def test_unknown_edge_cannot_authorize_retraction(self):
        data = self.edge_data()
        data["claims"][-1].update(status="UNKNOWN", support_evidence_ids=[])
        data["changes"][0]["operation"] = "RETRACT_DIRECT_DEPENDENCY"
        self.rejected(data, "Unknown/conflicting")

    def test_status_cannot_hide_negative_evidence(self):
        data = example("conflicting-identity")
        data["claims"][0]["status"] = "SUPPORTED"
        self.rejected(data, "status disagrees")

    def test_purl_cannot_disagree_with_candidate_version(self):
        data = example()
        data["candidates"][0]["purl"] = "pkg:maven/org.example/text@2.0"
        self.rejected(data, "identity fields disagree")

    def test_incomplete_inspection_is_not_complete_coverage(self):
        data = example("metadata-only")
        data["coverage"][0]["limitations"] = ["Nested archive was not read"]
        self.rejected(data, "cannot be complete")

    def test_runtime_safety_is_not_a_supported_output_of_this_contract(self):
        data = example()
        data["runtime_exploitability"] = "SAFE"
        self.rejected(data, "NOT_ASSESSED")

    def test_input_path_is_logical_and_cannot_traverse_bundle_boundary(self):
        data = json.loads((DESIGN / "examples/input.json").read_text())
        data["target"]["artifact"]["path"] = "../another.jar"
        with self.assertRaisesRegex(ValidationError, "bundle-relative"):
            ArtifactRequestV3.model_validate(data)

    def test_validation_does_not_mutate_the_observed_input(self):
        data = example()
        original = deepcopy(data)
        ArtifactAssessmentV3.model_validate(data)
        self.assertEqual(data, original)


if __name__ == "__main__":
    unittest.main()
