"""Synthetic scope/identity controls; coordinate matches are never truth labels."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from sbom_recovery.gold_contracts import CaseManifest,FrozenFile
from sbom_recovery.scope_audit import audit_scopes


class ScopeAuditTests(unittest.TestCase):
    def fixture(self,root,nodes,packages,relations=None,files=None):
        environment={"os":"linux","arch":"x86_64","runtime":"fixture"}
        native={"status":"COMPLETE","commit":"a"*40,"target":".","environment":environment,"nodes":nodes,"edges":[]}
        scanner={"spdxVersion":"SPDX-2.3","packages":packages,"relationships":relations or [],"files":files or []}
        (root/"native.json").write_text(json.dumps(native));(root/"scanner.json").write_text(json.dumps(scanner))
        case=CaseManifest(case_id="fixture",repository="https://example.invalid/demo",commit="a"*40,ecosystem="npm",
            environment=environment,evidence_cutoff="2026-11-02T00:00:00Z",files={
                key:FrozenFile(path=name,kind=kind,sha256=hashlib.sha256((root/name).read_bytes()).hexdigest())
                for key,name,kind in [("native","native.json","resolver"),("scanner","scanner.json","scanner")]},
            allowed_evidence=["native","scanner"],resolution_status="COMPLETE")
        path=root/"case.json";path.write_text(case.model_dump_json());return path,case

    def package(self,purl):
        return {"SPDXID":"pkg","name":"a","versionInfo":"1","externalRefs":[{"referenceType":"purl","referenceLocator":purl}]}

    def test_multiple_instances_are_ambiguous_and_never_promoted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path,_=self.fixture(root,[{"id":"one","name":"a","version":"1"},{"id":"two","name":"a","version":"1"}],[self.package("pkg:npm/a@1")])
            result=audit_scopes(path,root/"out")
            self.assertEqual(result["records"][0]["coordinate_status"],"EXACT_COORDINATES_MULTIPLE_INSTANCES")
            self.assertEqual(result["records"][0]["scope_judgment"],"CONTEXT_UNCERTAIN")
            self.assertEqual(result["promotion_count"],0)
            self.assertEqual(result["correctness"],"UNMEASURED")

    def test_version_and_qualifier_differences_are_only_family_candidates(self):
        for value in ["pkg:npm/a@2","pkg:npm/a@1?arch=arm64"]:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);path,_=self.fixture(root,[{"id":"one","name":"a","version":"1"}],[self.package(value)])
                result=audit_scopes(path,root/"out")
                self.assertEqual(result["records"][0]["coordinate_status"],"FAMILY_ONLY_DIFFERENT_COORDINATES")

    def test_namespace_and_ecosystem_are_not_name_only_matches(self):
        for value in ["pkg:npm/%40other/a@1","pkg:maven/org/a@1"]:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);path,_=self.fixture(root,[{"id":"one","name":"a","version":"1"}],[self.package(value)])
                result=audit_scopes(path,root/"out")
                self.assertEqual(result["records"][0]["candidate_instances"],[])

    def test_workflow_path_is_source_evidence_not_runtime_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);package=self.package("pkg:github/actions/checkout@v4")
            path,_=self.fixture(root,[],[package],relations=[{"spdxElementId":"pkg","relatedSpdxElement":"file","relationshipType":"OTHER","comment":"evident-by: file"}],
                files=[{"SPDXID":"file","fileName":".github/workflows/test.yml"}])
            row=audit_scopes(path,root/"out")["records"][0]
            self.assertEqual(row["path_roles"],["WORKFLOW_SOURCE"])
            self.assertEqual(row["scope_judgment"],"CONTEXT_UNCERTAIN")
            self.assertNotIn("false_positive",row)

    def test_private_annotation_files_are_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path,case=self.fixture(root,[],[self.package("pkg:npm/a@1")])
            case.files["private"]=FrozenFile(path="gold/missing-labels.json",sha256="b"*64,kind="annotation")
            path.write_text(case.model_dump_json())
            self.assertFalse(audit_scopes(path,root/"out")["gold_labels_read"])

    def test_wrong_native_environment_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path,case=self.fixture(root,[],[])
            case.environment["arch"]="arm64";path.write_text(case.model_dump_json())
            with self.assertRaisesRegex(ValueError,"another context"):audit_scopes(path,root/"out")
