"""Synthetic adversarial controls; these establish pipeline validity only."""
import base64
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile
from types import SimpleNamespace

from sbom_recovery.gold_contracts import fingerprint
from sbom_recovery.materialized_scope import (
    capture_inventory, digest, evaluate_scope, match_files, metadata_control,
    metadata_files, npm_instance, npm_snapshot, read_identity, scanner_path,
    tar_metadata, verify_integrity,
)
from scripts.run_materialized_scope import replay_target


def catalog_for(root,ecosystem="pypi"):
    entries=metadata_files(root,ecosystem)
    return {"schema_version":"materialized-evidence-v1","ecosystem":ecosystem,
            "entries":entries,"target_id":fingerprint(entries)}


def fixture(root,ecosystem="pypi",instance=None):
    relative=instance or "lib/python3.12/site-packages/demo.dist-info/METADATA"
    path=root/relative;path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text("Name: Demo_Project\nVersion: 2\n" if ecosystem=="pypi" else '{"name":"demo","version":"2"}')
    return catalog_for(root,ecosystem)


def document(entry,version="1"):
    return {"packages":[{"SPDXID":"pkg","name":"demo-project","versionInfo":version,
                         "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:pypi/demo-project@"+version}]}],
            "files":[{"SPDXID":"file","fileName":"/target/"+entry["path"],
                      "checksums":[{"algorithm":"SHA256","checksumValue":entry["sha256"]}]}],
            "relationships":[{"spdxElementId":"pkg","relatedSpdxElement":"file","relationshipType":"OTHER","comment":"evident-by: file"}]}


class MaterializedScopeTests(unittest.TestCase):
    def test_old_version_can_be_corrected_using_file_bytes_without_label_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);catalog=fixture(root);entry=catalog["entries"][0];doc=document(entry)
            binding=match_files(doc,catalog,root)
            self.assertEqual(binding["records"][0]["status"],"FILE_BOUND_INSTANCE")
            recovered,control=metadata_control(doc,catalog,root,binding)
            self.assertEqual(recovered["packages"][0]["versionInfo"],"2")
            self.assertEqual(recovered["packages"][0]["externalRefs"][0]["referenceLocator"],"pkg:pypi/demo-project@2")
            self.assertEqual(len(control["proposals"]),1)
            self.assertEqual(doc["packages"][0]["versionInfo"],"1")

    def test_correct_coordinates_cannot_override_wrong_file_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);catalog=fixture(root);doc=document(catalog["entries"][0],"2")
            doc["files"][0]["checksums"][0]["checksumValue"]="a"*64
            binding=match_files(doc,catalog,root)
            self.assertEqual(binding["records"][0]["status"],"UNKNOWN_CONTRADICTED_FILE_EVIDENCE")
            self.assertEqual(metadata_control(doc,catalog,root,binding)[1]["proposals"],[])

    def test_missing_strong_hash_is_uncertainty_not_a_contradiction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);catalog=fixture(root);doc=document(catalog["entries"][0])
            doc["files"][0]["checksums"]=[{"algorithm":"SHA1","checksumValue":"b"*40}]
            self.assertEqual(match_files(doc,catalog)["records"][0]["status"],"UNKNOWN_STRONG_DIGEST_UNAVAILABLE")

    def test_two_metadata_instances_are_not_collapsed_to_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);fixture(root)
            catalog=fixture(root,instance="lib/python3.12/site-packages/other.dist-info/METADATA")
            doc=document(catalog["entries"][0]);second=deepcopy(doc["files"][0]);second.update(SPDXID="second",fileName=catalog["entries"][1]["path"])
            second["checksums"][0]["checksumValue"]=catalog["entries"][1]["sha256"]
            doc["files"].append(second);doc["relationships"].append({"spdxElementId":"pkg","relatedSpdxElement":"second","relationshipType":"CONTAINS"})
            self.assertEqual(match_files(doc,catalog)["records"][0]["status"],"UNKNOWN_MULTIPLE_METADATA_INSTANCES")

    def test_nested_vendor_metadata_is_never_a_top_level_distribution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);catalog=fixture(root,instance="lib/python3.12/site-packages/pip/_vendor/demo.dist-info/METADATA")
            binding=match_files(document(catalog["entries"][0]),catalog)
            self.assertEqual(binding["records"][0]["status"],"OBSERVED_NESTED_METADATA")

    def test_duplicate_spdx_file_or_package_ids_fail_closed(self):
        for key in ["files","packages"]:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);catalog=fixture(root);doc=document(catalog["entries"][0]);doc[key].append(deepcopy(doc[key][0]))
                self.assertTrue(all(r["status"].startswith("UNKNOWN_") for r in match_files(doc,catalog)["records"]))

    def test_changed_catalog_or_forged_binding_proposals_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);catalog=fixture(root);doc=document(catalog["entries"][0]);binding=match_files(doc,catalog)
            altered=deepcopy(binding);altered["records"][0]["evidence_id"]="fabricated"
            with self.assertRaises(ValueError):metadata_control(doc,catalog,root,altered)
            catalog["entries"][0]["sha256"]="a"*64
            with self.assertRaises(ValueError):match_files(doc,catalog)

    def test_metadata_changed_after_catalog_is_not_used_for_correction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);catalog=fixture(root);entry=catalog["entries"][0];doc=document(entry);binding=match_files(doc,catalog)
            (root/entry["path"]).write_text("Name: invented\nVersion: 99\n")
            recovered,control=metadata_control(doc,catalog,root,binding)
            self.assertEqual(control["proposals"],[])
            self.assertEqual(len(control["unresolved"]),1)
            self.assertEqual(recovered,doc)

    def test_symlink_and_traversal_are_rejected(self):
        for path in ["../outside","/target/../outside","node_modules/../package.json",r"a\b"]:
            with self.assertRaises(ValueError):scanner_path(path)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);outside=root/"outside";outside.write_text("Name: demo\nVersion: 1\n")
            target=root/"target";target.mkdir();(target/"demo.dist-info").mkdir();(target/"demo.dist-info/METADATA").symlink_to(outside)
            with self.assertRaises(ValueError):metadata_files(target,"pypi")

    def test_native_disagreement_remains_unknown_with_undefined_score(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);target=root/"target";catalog=fixture(target);entry=catalog["entries"][0]
            native=root/"native.json";native.write_text(json.dumps({"installed":[{"metadata_location":"/out/target/"+entry["path"].rsplit("/",1)[0],"metadata":{"name":"demo-project","version":"99"}}]}))
            capture_inventory(target,"pypi",native,root/"inspection")
            reference=json.loads((root/"inspection/oracle/reference.json").read_text())
            self.assertEqual(reference["records"],[]);self.assertEqual(len(reference["issues"]),1)
            doc=document(entry);score=evaluate_scope(doc,doc,match_files(doc,catalog),reference)
            self.assertIsNone(score["identity_before"]["rate"])
            self.assertEqual(score["reference_eligible_records"],0)

    def test_empty_scope_does_not_generate_perfect_scores(self):
        score=evaluate_scope({"packages":[]},{"packages":[]},{"target_id":"empty","records":[]},{"target_id":"empty","records":[]})
        self.assertIsNone(score["version_after"]["rate"])

    def test_shared_jar_parser_is_excluded_from_native_accuracy_denominator(self):
        doc={"packages":[{"SPDXID":"p","versionInfo":"1","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:maven/org/a@1"}]}]}
        reference={"target_id":"t","native_source":"embedded pom.properties","records":[{"evidence_id":"e","version":"1","purl":"pkg:maven/org/a@1"}]}
        matches={"target_id":"t","records":[{"ref":"p","status":"FILE_BOUND_INSTANCE","evidence_id":"e"}]}
        score=evaluate_scope(doc,doc,matches,reference)
        self.assertEqual(score["metadata_only_records"],1)
        self.assertEqual(score["reference_eligible_records"],0)
        self.assertIsNone(score["version_before"]["rate"])

    def test_strongest_sri_must_match_and_sha1_alone_is_rejected(self):
        raw=b"artifact";good=base64.b64encode(hashlib.sha256(raw).digest()).decode();bad=base64.b64encode(hashlib.sha512(b"wrong").digest()).decode()
        verify_integrity(raw,"sha256-"+good)
        with self.assertRaises(ValueError):verify_integrity(raw,"sha256-"+good+" sha512-"+bad)
        with self.assertRaises(ValueError):verify_integrity(raw,"sha1-"+base64.b64encode(hashlib.sha1(raw).digest()).decode())

    def test_legacy_npm_archive_root_supported_but_ambiguous_metadata_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"pkg.tgz"
            for names,accepted in [(["Legacy-v1/package.json"],True),(["package/package.json","other/package.json"],False),(["../package.json"],False)]:
                with tarfile.open(path,"w:gz") as archive:
                    for name in names:
                        data=b'{"name":"demo","version":"1"}';info=tarfile.TarInfo(name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
                if accepted:self.assertEqual(tar_metadata(path)["name"],"demo")
                else:
                    with self.assertRaises(ValueError):tar_metadata(path)

    def test_npm_paths_and_repeated_physical_instances(self):
        for path in [".","../node_modules/a","node_modules/../a","/node_modules/a","node_modules/a//node_modules/b","node_modules/@/a"]:
            self.assertFalse(npm_instance(path),path)
        self.assertTrue(npm_instance("node_modules/@scope/a/node_modules/b"))
        a={"name":"a","version":"1","path":"/out/target/node_modules/a"}
        raw={"name":"root","version":"1","path":"/out/target","dependencies":{"a":a,"alias":deepcopy(a)}}
        self.assertEqual(len(npm_snapshot(raw)),2)
        raw["dependencies"]["alias"]["version"]="2"
        with self.assertRaises(ValueError):npm_snapshot(raw)

    def test_repeated_npm_occurrence_may_expand_additional_children(self):
        a={"name":"a","version":"1","path":"/out/target/node_modules/a"}
        expanded=deepcopy(a);expanded["dependencies"]={"b":{"name":"b","version":"2","path":"/out/target/node_modules/b"},"optional":{}}
        raw={"name":"root","version":"1","path":"/out/target","dependencies":{"a":a,"expanded":expanded}}
        issues=[];instances=npm_snapshot(raw,issues)
        self.assertEqual(set(instances),{"","node_modules/a","node_modules/b"})
        self.assertEqual(issues[0]["status"],"UNKNOWN")

    def test_lockfile_corrobates_all_instances_without_unique_instance_promotion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);instances=["node_modules/demo","node_modules/parent/node_modules/demo"]
            for instance in instances:fixture(root,"npm",instance+"/package.json")
            (root/"package-lock.json").write_text(json.dumps({"lockfileVersion":3,"packages":{p:{"name":"demo","version":"2"} for p in instances}}))
            catalog=catalog_for(root,"npm");entry=next(e for e in catalog["entries"] if e["format"]=="npm-lock");doc=document(entry,"2")
            doc["packages"][0]["externalRefs"][0]["referenceLocator"]="pkg:npm/demo@2"
            binding=match_files(doc,catalog,root);row=binding["records"][0]
            self.assertEqual(row["status"],"LOCK_CORROBORATED_COORDINATE_GROUP")
            self.assertIsNone(row["evidence_id"]);self.assertEqual(len(row["coordinate_group_evidence_ids"]),2)
            self.assertEqual(metadata_control(doc,catalog,root,binding)[1]["proposals"],[])
            doc["packages"][0]["externalRefs"][0]["referenceLocator"]+="?arch=arm64"
            self.assertEqual(match_files(doc,catalog,root)["records"][0]["status"],"UNKNOWN_LOCK_COORDINATES_UNSUPPORTED")

    def test_lock_contradictions_do_not_accept_coordinate_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);fixture(root,"npm","node_modules/demo/package.json")
            (root/"package-lock.json").write_text(json.dumps({"lockfileVersion":3,"packages":{"node_modules/demo":{"name":"demo","version":"99"}}}))
            catalog=catalog_for(root,"npm");entry=next(e for e in catalog["entries"] if e["format"]=="npm-lock");doc=document(entry,"2")
            doc["packages"][0]["externalRefs"][0]["referenceLocator"]="pkg:npm/demo@2"
            self.assertEqual(match_files(doc,catalog,root)["records"][0]["status"],"UNKNOWN_CONTRADICTED_FILE_EVIDENCE")

    def test_missing_or_ambiguous_jar_metadata_abstains(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=root/"a.jar"
            for members in [{"META-INF/MANIFEST.MF":"Manifest-Version: 1.0"},
                            {"META-INF/maven/a/a/pom.properties":"groupId=a\nartifactId=a\nversion=1", "META-INF/maven/b/b/pom.properties":"groupId=b\nartifactId=b\nversion=2"}]:
                with zipfile.ZipFile(path,"w") as archive:
                    for name,text in members.items():archive.writestr(name,text)
                with self.assertRaises(ValueError):read_identity(root,metadata_files(root,"maven")[0])

    def test_replay_requires_prior_success_and_unchanged_case_and_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cached=root/"retained/cases/demo";target=cached/"target";catalog=fixture(target)
            inspection=cached/"inspection/evidence";inspection.mkdir(parents=True)
            (inspection/"catalog.json").write_text(json.dumps(catalog))
            (cached/"oracle").mkdir();(cached/"oracle/native.json").write_text('{}')
            (cached/"source-context.json").write_text('{}');(cached/"install.log.json").write_text('{"returncode":0}')
            row={"case_id":"demo","status":"COMPLETE","parent_case_sha256":"expected","materialization_profile":"fixture"}
            manifest=root/"retained/manifest.json";manifest.write_text(json.dumps({"records":[row]}))
            case=SimpleNamespace(case_id="demo",ecosystem="pypi",digest=lambda:"expected")
            output=root/"out";output.mkdir()
            self.assertIn("REANALYSIS",replay_target(case,output,root/"retained"))
            self.assertEqual(metadata_files(output/"target","pypi"),catalog["entries"])
            for change in ["failed","different-case","changed-metadata"]:
                row.update(status="FAILED" if change=="failed" else "COMPLETE",parent_case_sha256="wrong" if change=="different-case" else "expected")
                manifest.write_text(json.dumps({"records":[row]}))
                if change=="changed-metadata":(target/catalog["entries"][0]["path"]).write_text("Name: demo\nVersion: 99\n")
                with self.assertRaises(ValueError):replay_target(case,root/"unused",root/"retained")


if __name__=="__main__":unittest.main()
