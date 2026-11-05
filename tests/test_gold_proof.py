"""Adversarial synthetic controls for independently addressable evidence."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from sbom_recovery.canonical import EvidenceItem, VerificationRecord
from sbom_recovery.gold_contracts import CaseManifest, ClaimV2, FrozenFile
from sbom_recovery.gold_pipeline import Builder
from sbom_recovery.proof import ProofReader, locator, pointer, select


def make_case(root, files, ecosystem="pypi", complete=False):
    case=CaseManifest(case_id="fixture",repository="https://example.invalid/project",commit="a"*40,
        ecosystem=ecosystem,environment={"os":"linux","arch":"x86_64","runtime":"fixture"},
        evidence_cutoff="2026-11-02T00:00:00Z",resolution_status="COMPLETE" if complete else "NOT_ATTEMPTED",
        files={key:FrozenFile(path=name,sha256=hashlib.sha256((root/name).read_bytes()).hexdigest(),kind=kind)
               for key,name,kind in files},allowed_evidence=[key for key,_,_ in files])
    path=root/"case.json";path.write_text(case.model_dump_json());return path,case


class ProofTests(unittest.TestCase):
    def test_pointer_escaping_and_invalid_array_indices(self):
        self.assertEqual(select({"@scope/pkg":{"~name":2}},pointer("@scope/pkg","~name")),2)
        for path in ["/01","/-1","/-","/1~2"]:
            with self.assertRaises((ValueError,KeyError,IndexError)): select([1,2],path)

    def test_poetry_name_is_proved_at_actual_poetry_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/"pyproject.toml").write_text('[tool.poetry]\nname="demo"\nversion="1"\nlicense="MIT"\n')
            path,_=make_case(root,[("manifest","pyproject.toml","manifest")])
            ledger=Builder(path).build();reader=ProofReader(path)
            self.assertEqual(reader.audit(ledger)["status"],"PASSED")
            name=next(c for c in ledger.claims if c.predicate=="name")
            self.assertEqual(reader.inspect(name,name.evidence[0])["selector"]["pointer"],"/tool/poetry/name")
            bad=name.model_copy(deep=True);bad.evidence[0].locator=locator("toml","/project/name")
            with self.assertRaises(KeyError): reader.inspect(bad,bad.evidence[0])

    def test_same_extractor_output_cannot_prove_fabricated_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/"package.json").write_text('{"name":"demo","version":"1"}')
            path,_=make_case(root,[("manifest","package.json","manifest")],"npm")
            claim=Builder(path).build().claims[0]
            claim.object="invented";claim.evidence[0].raw_value="invented"
            with self.assertRaisesRegex(ValueError,"support value"): ProofReader(path).inspect(claim,claim.evidence[0])

    def test_scoped_npm_dependency_uses_unambiguous_pointer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/"package.json").write_text(json.dumps({"name":"demo","version":"1","dependencies":{"@scope/pkg":"^2"}}))
            path,_=make_case(root,[("manifest","package.json","manifest")],"npm")
            claim=next(c for c in Builder(path).build().claims if c.predicate=="depends_on")
            proof=ProofReader(path).inspect(claim,claim.evidence[0])
            self.assertEqual(proof["selector"]["pointer"],"/dependencies/@scope~1pkg")

    def test_dependency_cannot_be_inferred_from_description(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/"pyproject.toml").write_text('[project]\nname="demo"\nversion="1"\ndescription="requests>=2"\ndependencies=["requests>=2"]\n')
            path,_=make_case(root,[("manifest","pyproject.toml","manifest")])
            claim=next(c for c in Builder(path).build().claims if c.predicate=="depends_on")
            claim.evidence[0].locator=locator("toml","/project/description","python-requirement")
            with self.assertRaisesRegex(ValueError,"not a declared"): ProofReader(path).inspect(claim,claim.evidence[0])

    def test_nested_package_name_cannot_be_used_as_root_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/"package.json").write_text('{"name":"demo","version":"1","nested":{"name":"demo"}}')
            path,_=make_case(root,[("manifest","package.json","manifest")],"npm")
            claim=next(c for c in Builder(path).build().claims if c.predicate=="name")
            claim.evidence[0].locator=locator("json","/nested/name")
            with self.assertRaisesRegex(ValueError,"root source metadata"):ProofReader(path).inspect(claim,claim.evidence[0])

    def test_markers_and_extra_scope_are_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/"pyproject.toml").write_text('[project]\nname="demo"\nversion="1"\n[project.optional-dependencies]\nfeature=[\'b; sys_platform == "linux"\']\n')
            path,_=make_case(root,[("manifest","pyproject.toml","manifest")])
            claim=next(c for c in Builder(path).build().claims if c.predicate=="depends_on")
            reader=ProofReader(path);reader.inspect(claim,claim.evidence[0])
            claim.scope="runtime_production"
            with self.assertRaisesRegex(ValueError,"scope mismatch"): reader.inspect(claim,claim.evidence[0])

    def test_wheel_checksum_is_whole_artifact_derivation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with zipfile.ZipFile(root/"demo.whl","w") as archive:
                archive.writestr("demo.dist-info/METADATA","Name: Demo_Project\nVersion: 1\n")
            path,case=make_case(root,[("wheel","demo.whl","artifact")])
            ledger=Builder(path).build();reader=ProofReader(path)
            self.assertEqual(reader.audit(ledger)["status"],"PASSED")
            claim=next(c for c in ledger.claims if c.predicate=="checksum")
            proof=reader.inspect(claim,claim.evidence[0])
            self.assertEqual(proof["selector"]["operation"],"checksum")
            self.assertNotIn("checksum",proof["raw_value"])
            self.assertEqual(proof["derived_value"],case.files["wheel"].sha256)

    def test_legacy_opaque_locator_is_reported_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/"package.json").write_text('{"name":"demo","version":"1"}')
            path,_=make_case(root,[("manifest","package.json","manifest")],"npm")
            ledger=Builder(path).build();ledger.claims[0].evidence[0].locator="name"
            audit=ProofReader(path).audit(ledger)
            self.assertEqual(audit["status"],"FAILED")
            self.assertIn("Legacy",audit["failures"][0]["error"])

    def test_positive_selector_cannot_be_relabelled_as_proven_absence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/"package.json").write_text('{"name":"demo","version":"1"}')
            path,_=make_case(root,[("manifest","package.json","manifest")],"npm")
            claim=Builder(path).build().claims[0];claim.status="verified_absent"
            with self.assertRaisesRegex(ValueError,"cannot prove absence"):
                ProofReader(path).inspect(claim,claim.evidence[0])

    def test_setup_is_read_without_executing_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/"setup.py").write_text('raise RuntimeError("MUST NOT EXECUTE")\nrequires=["b>=1"]\nsetup(name="demo",version="1",install_requires=requires)\n')
            path,_=make_case(root,[("manifest","setup.py","manifest")])
            ledger=Builder(path).build();self.assertEqual(ProofReader(path).audit(ledger)["status"],"PASSED")

    def test_inherited_maven_version_and_composite_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/"pom.xml").write_text('<project><parent><groupId>org.demo</groupId><version>2</version></parent><artifactId>demo</artifactId></project>')
            path,_=make_case(root,[("pom","pom.xml","manifest")],"maven")
            ledger=Builder(path).build();reader=ProofReader(path)
            self.assertEqual(reader.audit(ledger)["status"],"PASSED")
            version=next(c for c in ledger.claims if c.predicate=="version")
            self.assertEqual(reader.inspect(version,version.evidence[0])["selector"]["pointer"],"/parent/version")
