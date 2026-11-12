"""Multi-document occurrence bindings, evidence conflicts, and native export."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from sbom_recovery.core.formats import validate_native
from sbom_recovery.investigation.engine import ingest, reconcile, export
from sbom_recovery.reconciliation.merge_contracts_v3 import ReconciliationRequestV3


def document(version="1.0.0", locator="node_modules/lib"):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "bom-ref": "app", "name": "app", "version": "1.0.0",
                                        "purl": "pkg:npm/app@1.0.0",
                                        "properties": [{"name": "sbom-recovery:locator", "value": ""}]}},
            "components": [{"type": "library", "bom-ref": "dependency", "name": "lib", "version": version,
                            "purl": "pkg:npm/lib@" + version,
                            "properties": [{"name": "sbom-recovery:locator", "value": locator}]}],
            "dependencies": [{"ref": "app", "dependsOn": ["dependency"]}]}


def make_request(directory, docs):
    sources = []
    for index, doc in enumerate(docs):
        path = Path(directory) / (str(index) + ".json")
        path.write_text(json.dumps(doc))
        sources.append({"source_id": "tool-" + str(index), "document": {"path": path.name,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
                        "format": "CycloneDX" if doc.get("bomFormat") == "CycloneDX" else "SPDX",
                        "producer": {"name": "scanner"}, "target_id": "target", "revision_ref": "rev1",
                        "context_id": "linux", "view": "RESOLVED"})
    return ReconciliationRequestV3.model_validate({"target": {"target_id": "target", "project_ref": "app",
        "revision_ref": "rev1", "context": {"context_id": "linux"}, "view": "RESOLVED"},
        "documents": sources, "policy_id": "eager-v1"})


def evidence(version="1.0.0", source_id="native", edge=True, closure=False, locator="node_modules/lib"):
    return {"source_id": source_id, "kind": "native_resolution", "sha256": "a" * 64, "status": "OK",
            "facts": {"scope": {"target_id": "target", "revision_ref": "rev1", "context_id": "linux", "view": "RESOLVED"},
                      "components": [{"occurrence_id": "root", "locator": "", "ecosystem": "npm", "name": "app",
                                      "version": "1.0.0", "purl": "pkg:npm/app@1.0.0"},
                                     {"occurrence_id": "lib", "locator": locator, "ecosystem": "npm", "name": "lib",
                                      "version": version, "purl": "pkg:npm/lib@" + version}],
                      "edges": [{"source": "root", "target": "lib", "relationship_type": "direct_dependency",
                                 "scope": "unknown"}] if edge else [],
                      "coverage": [{"subject": "root", "domain": "direct_dependency", "complete": True}] if closure else []}}


class InvestigationEngineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def state(self, *docs):
        return ingest(make_request(self.directory.name, list(docs or (document(), document("2.0.0")))), self.directory.name)

    def test_namespace_reused_native_refs_without_choosing_winner(self):
        state = self.state()
        result = reconcile(state, [])
        self.assertEqual(len(state["observations"]), 4)
        self.assertEqual(len({o["observation_id"] for o in state["observations"]}), 4)
        self.assertEqual(len(result["components"]), 4)
        self.assertEqual({c["version"] for c in result["components"] if c["name"] == "lib"}, {"1.0.0", "2.0.0"})
        self.assertTrue(all(c["status"] == "UNKNOWN" for c in result["components"]))

    def test_rootless_inventory_exports_without_inventing_dependency_roots(self):
        docs = [document(), document("2.0.0")]
        for doc in docs:
            app = doc.pop("metadata")["component"]
            app["type"] = "library"
            doc["components"].append(app)
        result = reconcile(self.state(*docs), [])
        self.assertEqual(result["roots"], [])
        output = export(result)
        self.assertTrue(output["validation-report.json"]["valid"], output["validation-report.json"])
        # A subsequent consumer cannot reinterpret document subjects as paths.
        req = make_request(self.directory.name, [output["unified.cdx.json"], output["unified.cdx.json"]])
        spdx = output["unified.spdx.json"]
        raw = json.dumps(spdx).encode()
        path = Path(self.directory.name) / "rootless.spdx.json"
        path.write_bytes(raw)
        data = req.model_dump()
        for source in data["documents"]:
            source.update(format="SPDX", document={"path": path.name, "sha256": hashlib.sha256(raw).hexdigest()})
        self.assertEqual(reconcile(ingest(data, self.directory.name), [])["roots"], [])

    def test_locator_evidence_corrects_version_and_keeps_original_claim(self):
        result = reconcile(self.state(), [evidence("2.0.0")])
        self.assertEqual(len(result["components"]), 2)
        lib = next(c for c in result["components"] if c["name"] == "lib")
        self.assertEqual(lib["version"], "2.0.0")
        self.assertEqual(len(lib["observation_ids"]), 2)
        old = next(c for c in result["claims"] if c["predicate"] == "version" and c["value"] == "1.0.0"
                   and c["subject"] == lib["id"])
        self.assertEqual(old["status"], "REFUTED")
        self.assertTrue(any(e["status"] == "SUPPORTED" for e in result["edges"]))
        correction = next(d for d in result["decisions"] if d.get("field") == "version")
        self.assertEqual((correction["before"], correction["value"], correction["disposition"]), ("1.0.0", "2.0.0", "APPLY"))
        self.assertEqual(next(o for o in result["raw_observations"] if o["identity"]["version"] == "1.0.0"
                              and o["identity"]["name"] == "lib")["native_record"]["version"], "1.0.0")

    def test_same_purl_different_occurrences_never_collapse_without_binding(self):
        left, right = document(), document(locator="node_modules/outer/node_modules/lib")
        result = reconcile(self.state(left, right), [evidence()])
        libs = [c for c in result["components"] if c["name"] == "lib"]
        self.assertEqual(len(libs), 2)
        self.assertEqual(len({c["locator"] for c in libs}), 2)

    def test_two_evidence_versions_at_locator_remain_conflicting(self):
        result = reconcile(self.state(), [evidence("1.0.0"), evidence("2.0.0", "other")])
        lib = next(c for c in result["components"] if c["name"] == "lib")
        self.assertEqual(lib["status"], "CONFLICT")
        self.assertIsNone(lib["version"])
        self.assertIsNone(lib["purl"])
        self.assertTrue(result["conflicts"])
        self.assertFalse(any(e["status"] == "SUPPORTED" for e in result["edges"]))

    def test_wrong_scope_or_missing_scope_cannot_modify_observations(self):
        state = self.state()
        for changed in ({"context_id": "windows"}, {"revision_ref": None}, {"view": "ARTIFACT"}):
            source = evidence("2.0.0")
            source["facts"]["scope"].update(changed)
            result = reconcile(state, [source])
            self.assertEqual(len(result["components"]), 4)
            self.assertTrue(all(c["status"] == "UNKNOWN" for c in result["components"]))

    def test_missing_document_scope_not_filled_from_request(self):
        req = make_request(self.directory.name, [document(), document("2.0.0")])
        data = req.model_dump()
        data["documents"][0].update(revision_ref=None, context_id=None, view="UNKNOWN")
        result = reconcile(ingest(data, self.directory.name), [evidence("2.0.0")])
        unbound = [a for a in result["alignment"] if a["status"] == "UNRESOLVED"]
        self.assertEqual(len(unbound), 2)
        exported = export(result)["unified.cdx.json"]
        exported_edges = {(e["ref"], t) for e in exported.get("dependencies", []) for t in e["dependsOn"]}
        unbound_ids = {a["component_id"] for a in unbound}
        self.assertTrue(all(a not in unbound_ids and b not in unbound_ids for a, b in exported_edges))

    def test_partial_graph_absence_never_retracts_edge(self):
        result = reconcile(self.state(), [evidence("2.0.0", edge=False)])
        self.assertEqual({e["status"] for e in result["edges"]}, {"UNKNOWN"})
        self.assertEqual(result["path_absence_status"], "UNKNOWN")

    def test_closed_outgoing_graph_can_refute_same_scope_edge(self):
        result = reconcile(self.state(), [evidence("2.0.0", edge=False, closure=True)])
        self.assertEqual({e["status"] for e in result["edges"]}, {"REFUTED"})
        output = export(result)
        self.assertNotIn("dependencies", output["unified.cdx.json"])

    def test_disagreeing_closed_graph_yields_conflict_instead_of_priority(self):
        result = reconcile(self.state(), [evidence("2.0.0", closure=True),
                                          evidence("2.0.0", "other", edge=False, closure=True)])
        self.assertEqual({e["status"] for e in result["edges"]}, {"CONFLICT"})
        self.assertNotIn("dependencies", export(result)["unified.cdx.json"])

    def test_evidence_only_edge_conflict_is_independent_of_source_order(self):
        doc = document()
        doc.pop("dependencies")
        state = self.state(doc, doc)
        positive = evidence("1.0.0", "positive", edge=True, closure=True)
        negative = evidence("1.0.0", "negative", edge=False, closure=True)
        for sources in ([negative, positive], [positive, negative]):
            result = reconcile(state, sources)
            self.assertEqual({e["status"] for e in result["edges"]}, {"CONFLICT"})

    def test_manifest_cannot_self_assert_resolved_inventory(self):
        source = evidence("2.0.0")
        source["kind"] = "manifest"
        result = reconcile(self.state(), [source])
        self.assertEqual(len(result["components"]), 4)
        self.assertTrue(any(i["code"] == "EVIDENCE_KIND_NOT_ADMISSIBLE" for i in result["issues"]))

    def test_metadata_and_graph_ablations_do_not_alias_full_method(self):
        state, source = self.state(), evidence("2.0.0")
        a = reconcile(state, [source], metadata=True, graph=False)
        b = reconcile(state, [source], metadata=False, graph=True)
        self.assertEqual(len(a["components"]), 2)
        self.assertTrue(all(e["status"] == "UNKNOWN" for e in a["edges"]))
        self.assertTrue(any(c["name"] == "lib" and c["version"] == "1.0.0" for c in b["components"]))

    def test_standard_projections_validate_and_sidecar_keeps_source_fields(self):
        docs = [document(), document("2.0.0")]
        docs[0]["components"][0]["description"] = "Keep this producer metadata"
        result = reconcile(self.state(*docs), [evidence("2.0.0")])
        output = export(result)
        self.assertTrue(output["validation-report.json"]["valid"], output["validation-report.json"])
        self.assertTrue(validate_native(output["unified.spdx.json"])["valid"])
        self.assertTrue(validate_native(output["unified.cdx.json"])["valid"])
        self.assertIn("Keep this producer metadata", json.dumps(output["evidence.json"]))

    def test_frozen_digest_and_duplicate_refs_are_rejected(self):
        req = make_request(self.directory.name, [document(), document("2.0.0")])
        (Path(self.directory.name) / "0.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "digest"):
            ingest(req, self.directory.name)
        doc = document()
        doc["components"].append(deepcopy(doc["components"][0]))
        with self.assertRaisesRegex(ValueError, "Invalid native"):
            self.state(doc, document("2.0.0"))

    def test_identical_bytes_are_one_observation_not_two_votes(self):
        result = reconcile(self.state(document(), document()), [])
        self.assertEqual(len(result["components"]), 2)
        self.assertTrue(all(len(o["source_ids"]) == 2 for o in result["raw_observations"]))

    def test_identical_bytes_with_conflicting_scope_labels_do_not_export_known_scope_edges(self):
        req = make_request(self.directory.name, [document(), document()]).model_dump()
        req["documents"][1].update(context_id=None, revision_ref=None, view="UNKNOWN")
        result = reconcile(ingest(req, self.directory.name), [])
        self.assertEqual(len(result["components"]), 2)
        self.assertNotIn("dependencies", export(result)["unified.cdx.json"])

    def test_registry_never_grants_occurrence_binding(self):
        source = evidence("2.0.0")
        source["kind"] = "registry_metadata"
        result = reconcile(self.state(), [source])
        self.assertEqual(len(result["components"]), 4)
        self.assertFalse(any(c["status"] == "SUPPORTED" for c in result["components"]))

    def test_missing_observed_package_is_added_from_scoped_evidence(self):
        doc = document()
        doc["components"] = []
        doc.pop("dependencies")
        result = reconcile(self.state(doc, doc), [evidence()])
        self.assertEqual(len(result["components"]), 2)
        lib = next(c for c in result["components"] if c["name"] == "lib")
        self.assertEqual(lib["observation_ids"], [])
        self.assertEqual(lib["status"], "SUPPORTED")
        self.assertTrue(any(d["operation"] == "ADD_COMPONENT" and d["subject"] == lib["id"] for d in result["decisions"]))
        self.assertEqual(len([e for e in result["edges"] if e["status"] == "SUPPORTED"]), 1)

    def test_scoped_npm_names_are_bound_without_dropping_package(self):
        doc = document()
        doc["components"][0].update(name="@scope/lib", purl="pkg:npm/%40scope/lib@1.0.0")
        source = evidence()
        source["facts"]["components"][1].update(name="@scope/lib", purl="pkg:npm/%40scope/lib@1.0.0")
        result = reconcile(self.state(doc, doc), [source])
        libs = [c for c in result["components"] if c["name"] == "@scope/lib"]
        self.assertEqual(len(libs), 1)
        self.assertEqual(libs[0]["status"], "SUPPORTED")
        from sbom_recovery.investigation.security import assess, identity
        self.assertEqual(identity(libs[0]), ("npm", "@scope/lib", "1.0.0"))
        snapshot = {"schema_version": "osv-snapshot-v1", "advisories": [{"id": "TEST-SCOPED",
                    "affected": [{"package": {"ecosystem": "npm", "name": "@scope/lib"}, "versions": ["1.0.0"]}]}]}
        findings = assess(result, snapshot)["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "CONFIRMED_AFFECTED")

    def test_missing_origin_is_neutral_and_does_not_refute_known_origin(self):
        complete, partial = evidence("2.0.0", "complete"), evidence("2.0.0", "partial")
        complete["facts"]["components"][1]["origin"] = "https://registry.npmjs.org/lib"
        result = reconcile(self.state(), [complete, partial])
        lib = next(c for c in result["components"] if c["name"] == "lib")
        self.assertEqual(lib["status"], "SUPPORTED")
        self.assertEqual(lib["origin"], "https://registry.npmjs.org/lib")
        origin_claim = next(c for c in result["claims"] if c["subject"] == lib["id"] and c["predicate"] == "origin")
        self.assertEqual(origin_claim["support_evidence_ids"], ["complete"])

    def test_origin_disagreement_does_not_erase_supported_core_identity(self):
        left, right = evidence("2.0.0", "left"), evidence("2.0.0", "right")
        left["facts"]["components"][1]["origin"] = "https://one.example/lib"
        right["facts"]["components"][1]["origin"] = "https://two.example/lib"
        result = reconcile(self.state(), [left, right])
        lib = next(c for c in result["components"] if c["name"] == "lib")
        self.assertEqual(lib["status"], "SUPPORTED")
        self.assertEqual(lib["version"], "2.0.0")
        self.assertIsNone(lib["origin"])
        self.assertEqual(lib["field_statuses"]["origin"], "CONFLICT")
        self.assertTrue(any(c.get("field") == "origin" for c in result["conflicts"]))

    def test_spdx_relationship_direction_type_and_scope_remain_distinct(self):
        original = export(reconcile(self.state(), [evidence("2.0.0")]))["unified.spdx.json"]
        app = next(p["SPDXID"] for p in original["packages"] if p["name"] == "app")
        lib = next(p["SPDXID"] for p in original["packages"] if p["name"] == "lib")
        original["relationships"] = [{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": app, "relationshipType": "DESCRIBES"},
                                    {"spdxElementId": lib, "relatedSpdxElement": app, "relationshipType": "DEPENDENCY_OF"},
                                    {"spdxElementId": lib, "relatedSpdxElement": app, "relationshipType": "DEV_DEPENDENCY_OF"},
                                    {"spdxElementId": app, "relatedSpdxElement": lib, "relationshipType": "CONTAINS"}]
        result = reconcile(self.state(original, original), [])
        self.assertEqual({(e["relationship_type"], e["scope"]) for e in result["edges"]},
                         {("direct_dependency", "unknown"), ("direct_dependency", "development"), ("contains", "unknown")})
        by_id = {c["id"]: c for c in result["components"]}
        self.assertTrue(all(by_id[e["source"]]["name"] == "app" and by_id[e["target"]]["name"] == "lib" for e in result["edges"]))
        self.assertTrue(export(result)["validation-report.json"]["valid"])


if __name__ == "__main__":
    unittest.main()
