"""Behavioral scope/evidence tests: deliberately include real false positives."""
import copy
import tempfile
import unittest
from pathlib import Path

from public_evidence import admitted_artifact, parse_core_metadata, seeds_from_observed
from research_core import normalize_sbom, score_application, validate_cdx
from registry_provider import FrozenRegistryEvidenceProvider, build_evidence_snapshot
from resolver import ContextAwareResolver, DependencyRequirement, TargetEnvironment, evaluate_pep508_marker


def document():
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "components": [
                {"type": "library", "name": "app", "version": "1", "purl": "pkg:pypi/app@1", "bom-ref": "app-ref"},
                {"type": "library", "name": "dep", "version": "2", "purl": "pkg:pypi/dep@2", "bom-ref": "dep-ref"},
                {"type": "library", "name": "pip", "version": "24", "purl": "pkg:pypi/pip@24", "bom-ref": "pip-ref"},
                {"type": "file", "name": "README", "version": "1", "bom-ref": "file-ref"},
                {"type": "library", "name": "vendor", "version": "1", "purl": "pkg:pypi/vendor@1", "bom-ref": "vendor-ref",
                 "properties": [{"name": "syft:location:0:path", "value": "/venv/pip/_vendor/vendor/METADATA"}]}],
            "dependencies": [{"ref": "app-ref", "dependsOn": ["dep-ref"]},
                             {"ref": "pip-ref", "dependsOn": ["dep-ref"]}]}


class TestScopeAndScoring(unittest.TestCase):
    def test_files_vendor_root_mapping_and_original_immutability(self):
        original = document()
        before = copy.deepcopy(original)
        norm, audit = normalize_sbom(original, "app", bootstrap=["pip"])
        self.assertEqual(original, before)
        self.assertEqual(norm["metadata"]["component"]["purl"], "pkg:pypi/app@1")
        self.assertEqual(len(audit["components"]), 5)
        self.assertEqual({r["artifact_kind"] for r in audit["components"]}, {"DISTRIBUTION_CANDIDATE", "FILE", "VENDORED"})
        self.assertNotIn("pkg:pypi/readme@1", str(norm))
        self.assertNotIn("pkg:pypi/vendor@1", str(norm))
        self.assertTrue(validate_cdx(norm)["valid"])

    def test_no_arbitrary_root_or_false_complete_declarations(self):
        raw = document()
        raw.pop("dependencies")
        norm, audit = normalize_sbom(raw, "absent-root")
        self.assertNotIn("component", norm["metadata"])
        self.assertNotIn("dependencies", norm)
        self.assertEqual(audit["root_status"], "ROOT_UNKNOWN")

    def test_application_fp_is_retained_and_tooling_control_is_projected(self):
        norm, scope = normalize_sbom(document(), "app", bootstrap=["pip"])
        gold = {"nodes": [{"name": "app", "purl": "pkg:pypi/app@1"}, {"name": "dep", "purl": "pkg:pypi/dep@2"}],
                "edges": [{"from": "app", "to": "dep"}], "unresolved": []}
        edges = {("pkg:pypi/app@1", "pkg:pypi/dep@2"), ("pkg:pypi/pip@24", "pkg:pypi/dep@2"),
                 ("pkg:pypi/app@1", "pkg:pypi/not-in-truth@9")}
        score = score_application(gold, set(), edges, scope)
        self.assertEqual((score["whole_graph"]["tp"], score["whole_graph"]["fp"]), (1, 1))
        self.assertEqual(score["excluded_or_unknown_edges"], 1)
        self.assertEqual(score["whole_graph"]["precision"], .5)

    def test_unresolved_reference_is_not_a_negative_label(self):
        _, scope = normalize_sbom(document(), "app")
        gold = {"nodes": [{"name": "app", "purl": "pkg:pypi/app@1"}], "edges": [],
                "unresolved": [{"parent": "app", "reason": "invalid-metadata"}]}
        score = score_application(gold, set(), {("pkg:pypi/app@1", "pkg:pypi/unknown@1")}, scope)
        self.assertEqual(score["whole_graph"]["fp"], 0)
        self.assertIsNone(score["whole_graph"]["precision"])
        self.assertEqual(score["edge_audit"][0]["decision"], "UNKNOWN_LABEL")

    def test_identity_and_input_do_not_depend_on_oracle_membership(self):
        norm1, audit1 = normalize_sbom(document(), "app")
        oracle_a, oracle_b = {"app": "1"}, {"arbitrary": "999"}
        self.assertNotEqual(oracle_a, oracle_b)
        norm2, audit2 = normalize_sbom(document(), "app")
        self.assertEqual((norm1, audit1), (norm2, audit2))
        self.assertEqual(seeds_from_observed([norm1]), [("app", "1"), ("dep", "2"), ("pip", "24")])


class TestEvidenceSemantics(unittest.TestCase):
    def test_missing_metadata_and_verified_empty_are_distinct(self):
        with tempfile.TemporaryDirectory() as folder:
            build_evidence_snapshot({"empty@1": {"requires_dist": []}}, Path(folder))
            provider = FrozenRegistryEvidenceProvider(Path(folder))
            self.assertEqual(provider.get_requirements("pkg:pypi/empty@1"), [])
            self.assertIsNone(provider.get_requirements("pkg:pypi/missing@1"))
            provider.packages["empty@1"]["metadata_status"] = "DYNAMIC_UNRESOLVED"
            self.assertIsNone(provider.get_requirements("pkg:pypi/empty@1"))

    def test_sdist_old_metadata_is_not_complete(self):
        raw = b"Metadata-Version: 1.2\nName: demo\nVersion: 1\n\n"
        record = parse_core_metadata(raw, "demo", "1", "sdist-pkg-info")
        self.assertEqual(record["metadata_status"], "DYNAMIC_UNRESOLVED")
        self.assertEqual(parse_core_metadata(raw, "demo", "1", "independent-sdist-build")["metadata_status"], "COMPLETE")

    def test_temporal_python_and_artifact_tag_filters(self):
        artifact = {"filename": "demo-1-py3-none-any.whl", "packagetype": "bdist_wheel",
                    "upload_time_iso_8601": "2024-01-01T00:00:00Z", "requires_python": ">=3.10"}
        def admissible(a, cutoff="2026-01-01T00:00:00Z", tags=("py3-none-any",)):
            return admitted_artifact(a, cutoff, "3.11.16", tags)
        self.assertTrue(admissible(artifact)[0])
        self.assertEqual(admissible(artifact, cutoff="2023-01-01T00:00:00Z")[1], "FUTURE_ARTIFACT")
        self.assertEqual(admissible({**artifact, "requires_python": ">=3.12"})[1], "PYTHON_INCOMPATIBLE")
        self.assertEqual(admissible(artifact, tags=("cp311-cp311-win_amd64",))[1], "WHEEL_TAG_INCOMPATIBLE")

    def test_transitive_extras_are_local_and_propagated(self):
        class Provider:
            source_name = "synthetic-fixture"
            def get_requirements(self, purl):
                return {"pkg:pypi/app@1": [DependencyRequirement("pkg:pypi/dep@2", requested_extras={"feature"})],
                        "pkg:pypi/dep@2": [DependencyRequirement("pkg:pypi/extra@3", marker='extra == "feature"')],
                        "pkg:pypi/pip@24": [DependencyRequirement("pkg:pypi/wrong@1", marker='extra == "feature"')]}.get(purl)
        norm, _ = normalize_sbom(document(), "app")
        result = ContextAwareResolver(Provider()).resolve(norm, TargetEnvironment("posix", "linux", "x86_64", "3.11"))
        targets = {e["target_purl"] for e in result["G_candidate"]["edges"]}
        self.assertIn("pkg:pypi/extra@3", targets)
        self.assertNotIn("pkg:pypi/wrong@1", targets)

    def test_combined_markers_and_unknown_context(self):
        env = TargetEnvironment("posix", "linux", "x86_64", "3.11", active_extras={"socks"})
        self.assertTrue(evaluate_pep508_marker('(sys_platform == "linux" and extra == "socks") or python_version < "3.10"', env))
        self.assertFalse(evaluate_pep508_marker('sys_platform == "win32" and extra == "socks"', env))
        self.assertIsNone(evaluate_pep508_marker('not valid !!!', env))
        self.assertIsNone(evaluate_pep508_marker('platform_release == "host-kernel"', env))
