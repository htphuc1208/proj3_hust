"""Synthetic integrity controls, not empirical algorithm-quality evidence."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from sbom_recovery.formats import NativeDocument
from sbom_recovery.reconciliation import load_snapshot, reconcile
from sbom_recovery.targets import metadata_inventory
from tests.test_agent_recovery import context, document


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.target = Path(self.temp.name)
        self.ctx = context()
        self.doc = document()
        self.doc["dependencies"] = [{"ref": "a", "dependsOn": ["b"]}]
        self.put("alpha", 'Requires-Dist: beta; extra == "optional"\n')
        self.put("beta", "", "2")

    def put(self, name, requirements, version="1", directory=None):
        path = self.target / "lib/python3.11/site-packages" / (directory or f"{name}-{version}.dist-info") / "METADATA"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n{requirements}\n")
        return path

    def run_policy(self, ctx=None, doc=None):
        ctx = (ctx or self.ctx).model_copy(update={"target_id": metadata_inventory(self.target)[1]})
        snapshot = load_snapshot(self.target, ctx, "2026-10-28T00:00:00Z")
        return reconcile(doc or self.doc, ctx, snapshot)

    def test_inactive_extra_retracted_in_derived_view_only(self):
        before = deepcopy(self.doc)
        result = self.run_policy()
        self.assertEqual(result["retracted_edges"], [["a", "b"]])
        self.assertEqual(self.doc, before)
        self.assertFalse(NativeDocument(result["document"]).edges())
        self.assertEqual(result["document"]["version"], 2)
        self.assertEqual(result["path_absence_status"], "UNKNOWN")
        self.assertIsNone(result["confidence"])
        self.assertTrue(result["assessments"][0]["evidence"])

    def test_active_root_extra_prevents_retraction(self):
        r = self.run_policy(self.ctx.model_copy(update={"active_extras": ["optional"]}))
        self.assertFalse(r["retracted_edges"])
        self.assertEqual(r["counts"], {"SUPPORTED": 1})

    def test_transitive_optional_activation_is_preserved(self):
        self.put("root", "Requires-Dist: alpha[optional]\n")
        r = self.run_policy(self.ctx.model_copy(update={"root_purls": ["pkg:pypi/root@1"]}))
        self.assertFalse(r["retracted_edges"])
        self.assertEqual(r["assessments"][0]["known_extras"], ["optional"])

    def test_possible_transitive_activation_abstains(self):
        self.put("root", 'Requires-Dist: alpha[optional]; platform_release == "unknown"\n')
        r = self.run_policy(self.ctx.model_copy(update={"root_purls": ["pkg:pypi/root@1"]}))
        self.assertFalse(r["retracted_edges"])
        self.assertEqual(r["counts"], {"UNKNOWN": 1})
        self.assertEqual(r["assessments"][0]["possible_extras"], ["optional"])

    def test_unknown_host_marker_abstains(self):
        self.put("alpha", 'Requires-Dist: beta; implementation_name == "pypy"\n')
        self.assertEqual(self.run_policy()["counts"], {"UNKNOWN": 1})

    def test_mixed_active_and_inactive_declarations_keep_edge(self):
        self.put("alpha", 'Requires-Dist: beta; extra == "optional"\nRequires-Dist: beta>=2\n')
        self.assertEqual(self.run_policy()["counts"], {"SUPPORTED": 1})

    def test_no_matching_requirement_is_not_a_negative(self):
        self.put("alpha", "")
        self.assertEqual(self.run_policy()["counts"], {"UNKNOWN": 1})

    def test_version_mismatch_and_direct_url_are_unknown(self):
        for text in ("Requires-Dist: beta<2\n", "Requires-Dist: beta @ https://example.invalid/beta.whl\n"):
            with self.subTest(text=text):
                self.put("alpha", text)
                self.assertEqual(self.run_policy()["counts"], {"UNKNOWN": 1})

    def test_missing_or_malformed_metadata_prevents_retraction(self):
        self.put("unparsed", "Requires-Dist: !!!\n")
        r = self.run_policy()
        self.assertFalse(r["retracted_edges"])
        self.assertTrue(r["diagnostics"])
        (self.target / "lib/python3.11/site-packages/beta-2.dist-info/METADATA").unlink()
        self.assertFalse(self.run_policy()["retracted_edges"])

    def test_missing_root_context_abstains(self):
        self.assertFalse(self.run_policy(self.ctx.model_copy(update={"root_purls": []}))["retracted_edges"])

    def test_dynamic_requirements_abstain(self):
        self.put("alpha", 'Dynamic: Requires-Dist\nRequires-Dist: beta; extra == "optional"\n')
        self.assertFalse(self.run_policy()["retracted_edges"])

    def test_duplicate_metadata_and_multiple_versions_abstain(self):
        self.put("alpha", "", directory="duplicate.dist-info")
        self.assertFalse(self.run_policy()["retracted_edges"])
        self.put("alpha", "", "3")
        self.assertFalse(self.run_policy()["retracted_edges"])

    def test_duplicate_scanner_instances_and_qualified_purls_abstain(self):
        duplicate = deepcopy(self.doc)
        duplicate["components"].append({**duplicate["components"][0], "bom-ref": "b2"})
        self.assertFalse(self.run_policy(doc=duplicate)["retracted_edges"])
        qualified = deepcopy(self.doc)
        qualified["components"][0]["purl"] += "?arch=x86_64"
        self.assertFalse(self.run_policy(doc=qualified)["retracted_edges"])

    def test_duplicate_reference_does_not_bind(self):
        duplicate = deepcopy(self.doc)
        duplicate["components"].append(deepcopy(duplicate["components"][0]))
        self.assertFalse(self.run_policy(doc=duplicate)["retracted_edges"])

    def test_spdx_inverse_edges_removed_without_touching_other_relationships(self):
        def package(ref, name, version):
            return {"SPDXID": ref, "name": name, "versionInfo": version,
                    "externalRefs": [{"referenceType": "purl", "referenceLocator": f"pkg:pypi/{name}@{version}"}]}
        doc = {"spdxVersion": "SPDX-2.3", "packages": [package("a", "alpha", "1"), package("b", "beta", "2")],
               "relationships": [{"spdxElementId": "b", "relatedSpdxElement": "a", "relationshipType": "DEPENDENCY_OF"},
                                 {"spdxElementId": "a", "relatedSpdxElement": "b", "relationshipType": "CONTAINS"}]}
        result = self.run_policy(doc=doc)
        self.assertEqual(len(result["document"]["relationships"]), 1)
        self.assertEqual(result["document"]["relationships"][0]["relationshipType"], "CONTAINS")

    def test_future_unknown_availability_and_wrong_snapshot_rejected(self):
        ctx = self.ctx.model_copy(update={"target_id": metadata_inventory(self.target)[1]})
        for value in ("2027-01-01T00:00:00Z", "2026-10-28T00:00:00"):
            with self.assertRaises(ValueError):
                load_snapshot(self.target, ctx, value)
        with self.assertRaisesRegex(ValueError, "digest"):
            load_snapshot(self.target, self.ctx, "2026-10-28T00:00:00Z")

    def test_target_symlink_and_tamper_rejected(self):
        ctx = self.ctx.model_copy(update={"target_id": metadata_inventory(self.target)[1]})
        path = self.put("beta", "Requires-Dist: changed\n", "2")
        with self.assertRaisesRegex(ValueError, "digest"):
            load_snapshot(self.target, ctx, "2026-10-28T00:00:00Z")
        path.unlink()
        path.symlink_to(self.target / "lib/python3.11/site-packages/alpha-1.dist-info/METADATA")
        with self.assertRaisesRegex(ValueError, "SYMLINK"):
            metadata_inventory(self.target)


if __name__ == "__main__":
    unittest.main()
