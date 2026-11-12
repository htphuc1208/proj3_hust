"""Frozen acquisition boundaries and native evidence semantics."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from sbom_recovery.investigation.evidence import EvidenceCatalog, read_frozen_blob
from sbom_recovery.reconciliation.merge_contracts_v3 import ReconciliationRequestV3


SCOPE = {"target_id": "release", "revision_ref": "commit-123", "context_id": "linux-node20", "view": "RESOLVED"}


def snapshot():
    return {"schema_version": "reconciliation-evidence-v1", "target": deepcopy(SCOPE),
            "components": [{"occurrence_id": "root", "ecosystem": "npm", "name": "app", "version": "1.0.0", "locator": ""},
                           {"occurrence_id": "dep", "ecosystem": "npm", "name": "example", "version": "2.0.0", "locator": "node_modules/example"}],
            "edges": [{"source": "root", "target": "dep", "relationship_type": "direct_dependency", "scope": "runtime"}],
            "coverage": [{"subject": "root", "domain": "direct_dependency", "complete": True}]}


class EvidenceCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def catalog(self, payload=None, *, kind="native_resolution", relative="evidence/record.json", max_source_bytes=1048576):
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(snapshot() if payload is None else payload).encode()
        path.write_bytes(raw)
        document = {"path": "inputs/a.json", "sha256": "a" * 64}
        request = ReconciliationRequestV3.model_validate({
            "target": {"target_id": SCOPE["target_id"], "project_ref": "project", "revision_ref": SCOPE["revision_ref"],
                       "context": {"context_id": SCOPE["context_id"], "features_by_subject": {"root": None}}, "view": SCOPE["view"]},
            "documents": [{"source_id": "a", "document": document, "format": "CycloneDX", "producer": {"name": "A"},
                           "target_id": SCOPE["target_id"], "revision_ref": SCOPE["revision_ref"], "context_id": SCOPE["context_id"], "view": "RESOLVED"},
                          {"source_id": "b", "document": {"path": "inputs/b.json", "sha256": "b" * 64}, "format": "CycloneDX", "producer": {"name": "B"},
                           "target_id": SCOPE["target_id"], "revision_ref": SCOPE["revision_ref"], "context_id": SCOPE["context_id"], "view": "RESOLVED"}],
            "evidence": [{"source_id": "record", "blob": {"path": relative, "sha256": hashlib.sha256(raw).hexdigest()}, "kind": kind}],
            "policy_id": "test-policy"})
        return EvidenceCatalog(request, self.base, max_source_bytes=max_source_bytes)

    def native(self, fmt, data):
        return {"schema_version": "native-evidence-v1", "target": deepcopy(SCOPE), "format": fmt, "data": data}

    def test_frozen_scoped_snapshot_produces_valid_facts(self):
        catalog = self.catalog()
        result = catalog.acquire("record")
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["facts"]["scope"], SCOPE)
        self.assertEqual(result["facts"]["components"][1]["purl"], "pkg:npm/example@2.0.0")
        self.assertGreater(result["bytes_returned"], 0)
        self.assertEqual(result["content_role"], "UNTRUSTED_DATA")
        descriptors = catalog.descriptors()
        self.assertNotIn("path", descriptors[0])
        self.assertNotIn("components", descriptors[0])

    def test_snapshot_cannot_supply_its_own_observation_binding(self):
        data = snapshot()
        data["bindings"] = [{"document_sha256": "a" * 64, "native_ref": "wrong", "occurrence_id": "dep"}]
        result = self.catalog(data).acquire("record")
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["facts"]["bindings"], [])
        self.assertIn("ignored", result["limitations"][0])

    def test_missing_or_different_scope_never_admits_facts(self):
        for field in SCOPE:
            for replacement in (None, "different"):
                with self.subTest(field=field, replacement=replacement):
                    data = snapshot()
                    data["target"][field] = replacement
                    result = self.catalog(data).acquire("record")
                    self.assertEqual(result["status"], "ERROR")
                    self.assertEqual(result["facts"]["components"], [])

    def test_unknown_revision_cannot_bind(self):
        catalog = self.catalog()
        catalog.request.target.revision_ref = None
        result = catalog.acquire("record")
        self.assertEqual(result["status"], "ERROR")
        self.assertIn("Unknown target revision", result["error"])

    def test_digest_drift_is_rejected(self):
        catalog = self.catalog()
        (self.base / "evidence/record.json").write_text("{}")
        result = catalog.acquire("record")
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["bytes_returned"], 0)
        self.assertEqual(result["facts"]["components"], [])

    def test_unallowlisted_source_and_negative_budgets_rejected(self):
        catalog = self.catalog()
        self.assertEqual(catalog.acquire("../../etc/passwd")["status"], "ERROR")
        self.assertEqual(catalog.acquire("record", -1)["bytes_returned"], 0)
        with self.assertRaises(ValueError):
            EvidenceCatalog(catalog.request, self.base, max_source_bytes=-1)

    def test_truncation_charges_budget_without_partial_facts(self):
        catalog = self.catalog()
        result = catalog.acquire("record", remaining_bytes=10)
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["bytes_returned"], 10)
        self.assertEqual(result["facts"]["components"], [])
        self.assertEqual(catalog.acquire("record", 0)["bytes_returned"], 0)

    def test_source_size_limit_prevents_read(self):
        result = self.catalog(max_source_bytes=10).acquire("record")
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["bytes_returned"], 0)

    def test_oracle_like_paths_are_denied(self):
        for relative in ("oracle/record.json", "evidence/oracle.json", "evidence/gold-labels.json", "ground_truth/x.json", "annotations.json"):
            with self.subTest(relative=relative):
                result = self.catalog(relative=relative).acquire("record")
                self.assertEqual(result["status"], "ERROR")
                self.assertEqual(result["bytes_returned"], 0)

    def test_symlink_file_and_directory_are_rejected(self):
        catalog = self.catalog()
        source = self.base / "evidence/record.json"
        frozen = source.read_bytes()
        original = self.base / "real.json"
        original.write_bytes(frozen)
        source.unlink()
        source.symlink_to(original)
        self.assertEqual(catalog.acquire("record")["status"], "ERROR")
        source.unlink()
        (self.base / "evidence").rmdir()
        (self.base / "real").mkdir()
        (self.base / "real/record.json").write_bytes(frozen)
        (self.base / "evidence").symlink_to(self.base / "real", target_is_directory=True)
        self.assertEqual(catalog.acquire("record")["status"], "ERROR")

    def test_shared_reader_rejects_traversal_even_without_contract_validation(self):
        for path in ("../x", "/etc/passwd", "a//b", "a/./b", "a\\b", "a/../b"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                read_frozen_blob(self.base, path, "a" * 64, 1000)

    def test_registry_records_stay_candidates_even_with_target_and_coverage(self):
        data = snapshot()
        data["coverage"].append({"subject": "*", "domain": "components", "complete": True})
        result = self.catalog(data, kind="registry_metadata").acquire("record")
        self.assertEqual(result["status"], "OK")
        self.assertTrue(result["candidate_only"])
        self.assertEqual(result["facts"]["scope"], {})
        self.assertEqual(result["facts"]["edges"], [])
        self.assertEqual(result["facts"]["coverage"], [])

    def test_registry_native_metadata_is_candidate_identity(self):
        result = self.catalog({"info": {"name": "requests", "version": "2.32.0"}}, kind="registry_metadata").acquire("record")
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["facts"]["components"][0]["purl"], "pkg:pypi/requests@2.32.0")

    def test_unwrapped_lockfile_has_no_implicit_scope(self):
        result = self.catalog({"lockfileVersion": 3, "packages": {}}, kind="lockfile").acquire("record")
        self.assertEqual(result["status"], "ERROR")

    def test_snapshot_identity_disagreement_and_dangling_edge_fail_closed(self):
        for bad in ("identity", "edge", "duplicate", "coverage"):
            data = snapshot()
            if bad == "identity":
                data["components"][1]["purl"] = "pkg:npm/example@999.0.0"
            elif bad == "edge":
                data["edges"][0]["target"] = "missing"
            elif bad == "duplicate":
                data["components"].append(deepcopy(data["components"][0]))
            else:
                data["coverage"][0]["complete"] = "true"
            with self.subTest(bad=bad):
                result = self.catalog(data).acquire("record")
                self.assertEqual(result["status"], "ERROR")
                self.assertEqual(result["facts"]["components"], [])

    def test_native_npm_lock_preserves_versions_alias_identity_and_nested_resolution(self):
        lock = {"lockfileVersion": 3, "name": "app", "version": "1.0.0", "packages": {
            "": {"name": "app", "version": "1.0.0", "dependencies": {"left": "1", "alias": "npm:real@2", "shared": "2"}},
            "node_modules/left": {"version": "1.0.0", "dependencies": {"shared": "1"}},
            "node_modules/left/node_modules/shared": {"version": "1.0.0"},
            "node_modules/shared": {"version": "2.0.0"},
            "node_modules/alias": {"name": "real", "version": "2.0.0"},
            "node_modules/workspace": {"link": True, "resolved": "packages/workspace"}}}
        result = self.catalog(self.native("npm-lock", lock), kind="lockfile").acquire("record")
        self.assertEqual(result["status"], "OK", result)
        facts = result["facts"]
        self.assertEqual(len(facts["components"]), 5)
        self.assertEqual(next(c for c in facts["components"] if c["locator"] == "node_modules/alias")["purl"], "pkg:npm/real@2.0.0")
        self.assertIn({"source": "npm:node_modules/left", "target": "npm:node_modules/left/node_modules/shared",
                       "relationship_type": "direct_dependency", "scope": "runtime"}, facts["edges"])
        self.assertEqual(facts["coverage"], [])

    def test_native_lock_scoped_names_and_empty_dependencies_not_closure(self):
        lock = {"lockfileVersion": 2, "name": "app", "version": "1", "packages": {
            "": {"name": "app", "version": "1", "dependencies": {"@scope/name": "2"}},
            "node_modules/@scope/name": {"version": "2", "dependencies": {}}}}
        result = self.catalog(self.native("npm-lock", lock)).acquire("record")
        self.assertEqual(result["status"], "OK", result)
        self.assertEqual(result["facts"]["components"][1]["purl"], "pkg:npm/%40scope/name@2")
        self.assertEqual(result["facts"]["coverage"], [])

    def test_npm_ls_preserves_occurrences_and_does_not_assert_physical_closure(self):
        native = {"name": "app", "version": "1", "dependencies": {"a": {"version": "2", "dependencies": {"a": {"version": "1"}}}}}
        result = self.catalog(self.native("npm-ls", native)).acquire("record")
        self.assertEqual(result["status"], "OK", result)
        self.assertEqual(len(result["facts"]["components"]), 3)
        self.assertEqual(len(result["facts"]["edges"]), 2)
        self.assertEqual(result["facts"]["coverage"], [])
        native["problems"] = ["missing: a"]
        self.assertEqual(self.catalog(self.native("npm-ls", native)).acquire("record")["status"], "ERROR")

    def test_cargo_metadata_retains_kind_and_defers_target_conditional_edges(self):
        native = {"packages": [{"id": "app", "name": "app", "version": "1.0.0", "manifest_path": "/work/Cargo.toml"},
                               {"id": "dep", "name": "dep", "version": "2.0.0", "source": "registry+https://example.invalid"}],
                  "resolve": {"root": "app", "nodes": [{"id": "app", "deps": [{"pkg": "dep", "dep_kinds": [
                      {"kind": "build", "target": None}, {"kind": "dev", "target": "cfg(windows)"}]}]},
                                         {"id": "dep", "deps": []}]}}
        result = self.catalog(self.native("cargo-metadata", native)).acquire("record")
        self.assertEqual(result["status"], "OK", result)
        self.assertEqual(result["facts"]["edges"], [{"source": "app", "target": "dep", "relationship_type": "direct_dependency", "scope": "build"}])
        self.assertEqual(result["facts"]["coverage"], [])

    def cargo_fixture(self):
        return {"packages": [
            {"id": key, "name": key, "version": "1.0.0", "manifest_path": "/work/" + key + "/Cargo.toml"}
            for key in ("app", "portable", "windows-only", "windows-child", "unused", "no-node")],
            "workspace_members": ["app"], "workspace_default_members": ["app"],
            "resolve": {"root": "app", "nodes": [
                {"id": "app", "deps": [
                    {"pkg": "portable", "dep_kinds": [{"kind": None, "target": None}]},
                    {"pkg": "windows-only", "dep_kinds": [{"kind": None, "target": "cfg(windows)"}]}]},
                {"id": "portable", "deps": []},
                {"id": "windows-only", "deps": [{"pkg": "windows-child", "dep_kinds": [{"kind": None, "target": None}]}]},
                {"id": "windows-child", "deps": []}, {"id": "unused", "deps": []}]}}

    def test_cargo_all_platform_package_table_does_not_promote_conditional_packages(self):
        native = self.cargo_fixture()
        result = self.catalog(self.native("cargo-metadata", native)).acquire("record")
        self.assertEqual(result["status"], "OK", result)
        self.assertEqual({c["name"] for c in result["facts"]["components"]}, {"app", "portable"})
        self.assertEqual({c["name"] for c in result["facts"]["deferred_components"]},
                         {"windows-only", "windows-child", "unused", "no-node"})
        self.assertEqual(result["facts"]["edges"], [{"source": "app", "target": "portable",
                         "relationship_type": "direct_dependency", "scope": "runtime"}])
        self.assertTrue(result["facts"]["deferred_edges"])
        self.assertEqual(result["facts"]["coverage"], [])
        from sbom_recovery.investigation.engine import reconcile
        catalog = self.catalog(self.native("cargo-metadata", native))
        state = {"target": catalog.request.target.model_dump(), "observations": [], "source_documents": [],
                 "source_edges": [], "issues": []}
        prediction = reconcile(state, [catalog.acquire("record")])
        self.assertEqual({c["name"] for c in prediction["components"] if c["status"] == "SUPPORTED"}, {"app", "portable"})

    def test_cargo_conditional_package_can_be_selected_by_an_independent_unconditional_path(self):
        native = self.cargo_fixture()
        native["resolve"]["nodes"][1]["deps"] = [{"pkg": "windows-only", "dep_kinds": [{"kind": None, "target": None}]}]
        result = self.catalog(self.native("cargo-metadata", native)).acquire("record")
        self.assertEqual(result["status"], "OK", result)
        self.assertEqual({c["name"] for c in result["facts"]["components"]}, {"app", "portable", "windows-only", "windows-child"})
        self.assertNotIn({"source": "app", "target": "windows-only", "relationship_type": "direct_dependency", "scope": "runtime"}, result["facts"]["edges"])

    def test_cargo_default_workspace_members_take_priority_and_empty_remains_empty(self):
        native = self.cargo_fixture()
        native["resolve"]["root"] = None
        native["workspace_members"] = ["app", "unused"]
        result = self.catalog(self.native("cargo-metadata", native)).acquire("record")
        self.assertEqual({c["name"] for c in result["facts"]["components"]}, {"app", "portable"})
        native["workspace_default_members"] = []
        result = self.catalog(self.native("cargo-metadata", native)).acquire("record")
        self.assertEqual(result["status"], "OK", result)
        self.assertEqual(result["facts"]["components"], [])
        self.assertEqual(len(result["facts"]["deferred_components"]), 6)

    def test_cargo_missing_roots_cannot_imply_every_package_is_selected(self):
        native = self.cargo_fixture()
        native["resolve"]["root"] = None
        del native["workspace_default_members"]
        del native["workspace_members"]
        result = self.catalog(self.native("cargo-metadata", native)).acquire("record")
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["facts"]["components"], [])
        self.assertIn("roots", result["error"])

    def test_cargo_untyped_legacy_dependencies_and_missing_resolve_nodes_are_deferred(self):
        native = self.cargo_fixture()
        node = native["resolve"]["nodes"][0]
        node.pop("deps")
        node["dependencies"] = ["portable", "windows-only"]
        result = self.catalog(self.native("cargo-metadata", native)).acquire("record")
        self.assertEqual({c["name"] for c in result["facts"]["components"]}, {"app"})
        node["deps"] = [{"pkg": "no-node", "dep_kinds": [{"kind": None, "target": None}]}]
        result = self.catalog(self.native("cargo-metadata", native)).acquire("record")
        self.assertEqual({c["name"] for c in result["facts"]["components"]}, {"app"})

    def platform_lock(self):
        return {"lockfileVersion": 3, "name": "app", "version": "1.0.0", "packages": {
            "": {"name": "app", "version": "1.0.0", "dependencies": {
                "portable": "1", "windows-only": "1", "optional": "1", "cpu-specific": "1"}},
            "node_modules/portable": {"version": "1.0.0"},
            "node_modules/windows-only": {"version": "1.0.0", "os": ["win32"], "dependencies": {"windows-child": "1"}},
            "node_modules/windows-child": {"version": "1.0.0"},
            "node_modules/optional": {"version": "1.0.0", "optional": True, "dependencies": {"optional-child": "1"}},
            "node_modules/optional-child": {"version": "1.0.0"},
            "node_modules/cpu-specific": {"version": "1.0.0", "cpu": ["arm64"]}}}

    def test_npm_lock_platform_optional_and_their_children_do_not_become_target_facts(self):
        catalog = self.catalog(self.native("npm-lock", self.platform_lock()), kind="lockfile")
        catalog.request.target.context.os = "linux"
        catalog.request.target.context.architecture = "amd64"
        result = catalog.acquire("record")
        self.assertEqual(result["status"], "OK", result)
        self.assertEqual({c["name"] for c in result["facts"]["components"]}, {"app", "portable"})
        self.assertEqual(len(result["facts"]["deferred_components"]), 5)
        self.assertEqual(len(result["facts"]["edges"]), 1)
        self.assertEqual(result["facts"]["coverage"], [])

    def test_npm_lock_known_platform_selectors_can_be_evaluated_without_host_defaults(self):
        catalog = self.catalog(self.native("npm-lock", self.platform_lock()))
        catalog.request.target.context.os = "Windows"
        catalog.request.target.context.architecture = "aarch64"
        result = catalog.acquire("record")
        self.assertEqual({c["name"] for c in result["facts"]["components"]},
                         {"app", "portable", "windows-only", "windows-child", "cpu-specific"})

    def test_npm_lock_missing_platform_context_and_dev_optional_markers_stay_deferred(self):
        lock = self.platform_lock()
        lock["packages"]["node_modules/portable"]["devOptional"] = True
        result = self.catalog(self.native("npm-lock", lock)).acquire("record")
        self.assertEqual(result["status"], "OK", result)
        self.assertEqual({c["name"] for c in result["facts"]["components"]}, {"app"})
        reasons = {c["reason"] for c in result["facts"]["deferred_components"]}
        self.assertIn("UNKNOWN_PLATFORM_CONTEXT", reasons)
        self.assertIn("OPTIONAL_SELECTION_NOT_ESTABLISHED", reasons)

    def test_npm_optional_declaration_overrides_required_and_needs_selection_evidence(self):
        lock = {"lockfileVersion": 3, "packages": {
            "": {"name": "app", "version": "1", "dependencies": {"optional": "1"}, "optionalDependencies": {"optional": "1"}},
            "node_modules/optional": {"version": "1"}}}
        result = self.catalog(self.native("npm-lock", lock)).acquire("record")
        self.assertEqual({c["name"] for c in result["facts"]["components"]}, {"app"})
        self.assertEqual(result["facts"]["edges"], [])

    def test_npm_platform_negation_and_development_scope_are_explicit(self):
        lock = {"lockfileVersion": 3, "packages": {
            "": {"name": "app", "version": "1", "dependencies": {"dep": "1"}, "devDependencies": {"dev": "1"}},
            "node_modules/dep": {"version": "1", "os": ["!win32"]},
            "node_modules/dev": {"version": "1", "dev": True}}}
        catalog = self.catalog(self.native("npm-lock", lock))
        catalog.request.target.context.os = "linux"
        result = catalog.acquire("record")
        self.assertEqual({c["name"] for c in result["facts"]["components"]}, {"app", "dep"})
        catalog.request.target.context.build_profile = "development"
        result = catalog.acquire("record")
        self.assertEqual({c["name"] for c in result["facts"]["components"]}, {"app", "dep", "dev"})
        self.assertIn("development", {e["scope"] for e in result["facts"]["edges"]})

    def test_npm_any_selector_is_wildcard_only_as_a_singleton(self):
        lock = {"lockfileVersion": 3, "packages": {
            "": {"name": "app", "version": "1", "dependencies": {"dep": "1"}},
            "node_modules/dep": {"version": "1", "os": ["any", "!win32"]}}}
        catalog = self.catalog(self.native("npm-lock", lock))
        catalog.request.target.context.os = "linux"
        self.assertEqual({c["name"] for c in catalog.acquire("record")["facts"]["components"]}, {"app"})
        lock["packages"]["node_modules/dep"]["os"] = ["any"]
        result = self.catalog(self.native("npm-lock", lock)).acquire("record")
        self.assertEqual({c["name"] for c in result["facts"]["components"]}, {"app", "dep"})

    def test_npm_resolution_can_reach_dependencies_without_root_version_but_needs_root_record(self):
        lock = {"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"dep": "1"}}, "node_modules/dep": {"version": "1"}}}
        result = self.catalog(self.native("npm-lock", lock)).acquire("record")
        self.assertEqual(result["status"], "OK", result)
        self.assertEqual({c["name"] for c in result["facts"]["components"]}, {"dep"})
        del lock["packages"][""]
        self.assertEqual(self.catalog(self.native("npm-lock", lock)).acquire("record")["status"], "ERROR")

    def test_resolution_wrapper_cannot_claim_artifact_view(self):
        data = self.native("npm-ls", {"name": "app", "version": "1"})
        data["target"]["view"] = "ARTIFACT"
        catalog = self.catalog(data)
        catalog.request.target.view = "ARTIFACT"
        result = catalog.acquire("record")
        self.assertEqual(result["status"], "ERROR")
        self.assertIn("RESOLVED", result["error"])


if __name__ == "__main__":
    unittest.main()
