"""Synthetic contract/adversarial tests; these are not algorithm-quality measurements."""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx

from sbom_recovery.agent import ToolBroker, run_agent
from sbom_recovery.contracts import TargetContext
from sbom_recovery.evidence import EvidenceStore
from sbom_recovery.formats import NativeDocument, canonical_purl, sha, validate_native
from sbom_recovery.llm import Gateway, GatewayError
from sbom_recovery.metrics import controlled_mask, evaluate, paired_bootstrap, risk_coverage
from sbom_recovery.verifier import proposals_from_claims, verify


def document():
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": "alpha", "version": "1",
                "purl": "pkg:pypi/alpha@1", "bom-ref": "a"}},
            "components": [{"type": "library", "name": "beta", "version": "2", "purl": "pkg:pypi/beta@2", "bom-ref": "b"}],
            "properties": [{"name": "keep", "value": "unchanged"}]}


def context():
    return TargetContext(os_name="posix", sys_platform="linux", platform_machine="x86_64", python_version="3.11",
        python_full_version="3.11.16", platform_system="Linux", active_extras=[], target_id="target-digest",
        evidence_cutoff="2026-10-29T23:59:59Z", root_purls=["pkg:pypi/alpha@1"])


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = EvidenceStore(self.tmp.name)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def target(self, text, target_id="target-digest"):
        return self.store.add(text.encode(), source="target:" + sha(text), kind="target_metadata",
                              target_id=target_id, authority="VERIFIED_TARGET", available_at="2026-10-28T00:00:00Z")

    def facts(self, doc=None, ctx=None):
        d = doc or document()
        return proposals_from_claims(d, self.store.claims(d, ctx or context()))

    def test_target_evidence_recovers_edge_without_b3_and_preserves_input(self):
        self.target("Name: alpha\nVersion: 1\nRequires-Dist: beta>=2\n")
        self.target("Name: beta\nVersion: 2\n")
        doc = document()
        before = deepcopy(doc)
        result = verify(doc, self.store, context(), self.facts())
        self.assertTrue(result["validation"]["valid"], result["validation"])
        self.assertIn(("a", "b"), NativeDocument(result["document"]).edges())
        self.assertEqual(doc, before)
        self.assertNotIn("calibration", result)
        self.assertEqual(result["document"]["properties"], before["properties"])

    def test_missing_component_recovery_is_target_bound(self):
        self.target("Name: alpha\nVersion: 1\nRequires-Dist: beta>=2\n")
        self.target("Name: beta\nVersion: 2\n")
        d = document(); d["components"] = []
        result = verify(d, self.store, context(), self.facts(d))
        self.assertEqual(len(NativeDocument(result["document"]).packages()), 2)
        self.assertEqual(len(NativeDocument(result["document"]).edges()), 1)

    def test_registry_metadata_cannot_prove_target(self):
        self.store.add({"purl": "pkg:pypi/alpha@1", "info": {"name": "alpha", "version": "1", "license_expression": "MIT",
                       "requires_dist": ["beta>=2"]}}, source="https://pypi.org/alpha/1", kind="registry")
        result = verify(document(), self.store, context(), self.facts())
        self.assertFalse(result["accepted"])
        self.assertTrue(result["supported"])

    def test_wrong_target_context_and_explicit_empty_abstain(self):
        self.target("Name: alpha\nVersion: 1\nRequires-Dist: beta\n")
        self.target("Name: beta\nVersion: 2\n")
        d = document(); d["dependencies"] = [{"ref": "a", "dependsOn": []}]
        r = verify(d, self.store, context(), self.facts(d))
        self.assertTrue(any(x.get("reason") == "CONTRADICTED_DECLARATION" for x in r["supported"]))
        self.assertFalse(NativeDocument(r["document"]).edges())
        wrong = context().model_copy(update={"target_id": "other"})
        r = verify(document(), self.store, wrong, self.facts())
        self.assertFalse(r["accepted"])
        r = verify(document(), self.store, None, self.facts())
        self.assertFalse(r["accepted"])

    def test_inactive_and_unknown_markers_do_not_become_edges(self):
        self.target('Name: alpha\nVersion: 1\nRequires-Dist: beta; sys_platform == "win32"\nRequires-Dist: beta; platform_release == "x"\n')
        self.target("Name: beta\nVersion: 2\n")
        self.assertFalse([p for p in self.facts() if p["operation"] == "add_dependency"])

    def test_weak_evidence_cannot_activate_verified_target_extras(self):
        self.target("Name: alpha\nVersion: 1\nRequires-Dist: beta\n")
        self.target('Name: beta\nVersion: 2\nRequires-Dist: gamma; extra == "danger"\n')
        self.target("Name: gamma\nVersion: 3\n")
        self.store.add({"purl":"pkg:pypi/alpha@1","info":{"name":"alpha","version":"1","requires_dist":["beta[danger]"]}},
                       source="malicious registry",kind="registry")
        claims=self.store.claims(document(),context())
        self.assertFalse([c for c in claims if c["operation"]=="add_dependency" and c["subject"]=="b"
                          and c["authority"]=="VERIFIED_TARGET"])

    def test_source_manifest_declarations_remain_supported_candidates(self):
        self.store.add(b'[project]\nname="alpha"\nversion="1"\ndependencies=["beta>=2"]\n',source="source:pyproject.toml",kind="source_file")
        claims=self.store.claims(document(),context())
        edges=[c for c in claims if c["operation"]=="add_dependency"]
        self.assertTrue(edges)
        self.assertTrue(all(c["authority"]=="SUPPORTED" for c in edges))

    def test_fabricated_value_citation_and_tampered_blob(self):
        eid = self.target("Name: alpha\nVersion: 1\nLicense-Expression: MIT\n")
        proposal = next(p for p in self.facts() if p["field"] == "licenses")
        proposal["value"] = [{"expression": "Apache-2.0"}]
        self.assertEqual(verify(document(), self.store, context(), [proposal])["rejected"][0]["reason"], "NO_SUPPORTING_FACT")
        record, _ = self.store.read(eid)
        (Path(self.tmp.name) / "blobs" / record.sha256).write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "DIGEST"):
            self.store.claims(document(), context())

    def test_record_authority_cannot_be_tampered_without_breaking_binding(self):
        eid=self.store.add({"info": {}}, source="registry", kind="registry")
        record=self.store.records()[0].model_dump();record["authority"]="VERIFIED_TARGET"
        self.store.db.execute("UPDATE evidence SET record=? WHERE id=?",(json.dumps(record),eid));self.store.db.commit()
        with self.assertRaisesRegex(ValueError,"MANIFEST_DIGEST"):
            self.store.read(eid)

    def test_future_evidence_is_ineligible(self):
        self.store.add(b"Name: alpha\nVersion: 9\n",source="future",kind="target_metadata",authority="VERIFIED_TARGET",
                       target_id=context().target_id,available_at="2027-01-01T00:00:00Z")
        self.assertFalse(self.facts())

    def test_preserve_native_security_refs_and_purl_qualifiers(self):
        from sbom_recovery.baselines import coverage
        d={"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"a","name":"alpha","versionInfo":"1",
            "externalRefs":[{"referenceCategory":"SECURITY","referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a:x:alpha:1:*:*:*:*:*:*:*"},
                            {"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:pypi/alpha@1?arch=x86_64"}]}]}
        self.target("Name: alpha\nVersion: 1\n")
        proposals=self.facts(d)
        self.assertFalse([p for p in proposals if p["field"]=="externalRefs"])

    def test_false_shortcut_cannot_receive_vulnerability_recovery_credit(self):
        from sbom_recovery.security import vulnerability_recovery
        result=vulnerability_recovery({("a","b"),("b","c")},set(),{("a","c")},{"a"},{"c":["ADVISORY-TEST"]})
        self.assertEqual(result["vrr_after"],0.)

    def test_qualifiers_instances_and_unknown_fields_survive(self):
        self.assertEqual(canonical_purl("pkg:pypi/Foo_Bar@1?arch=x86_64"), "pkg:pypi/foo-bar@1?arch=x86_64")
        d = document(); d["components"].append({**d["components"][0], "bom-ref": "b2"})
        self.assertEqual(len(NativeDocument(d).packages()), 3)
        self.target("Name: beta\nVersion: 2\n")
        self.assertFalse(self.facts(d))

    def test_mask_does_not_turn_missing_declaration_into_zero(self):
        d = document(); d["dependencies"] = [{"ref": "a", "dependsOn": ["b"]}]
        masked, audit = controlled_mask(d, 1., 42, "dependency")
        self.assertEqual(masked["dependencies"], [])
        self.assertIsNone(NativeDocument(masked).declaration("a"))
        self.assertEqual(len(audit["removed"]), 1)

    def test_graph_relations_are_not_cooccurrence(self):
        d = {"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "a"}, {"SPDXID": "b"}],
             "relationships": [{"spdxElementId": "a", "relatedSpdxElement": "b", "relationshipType": "CONTAINS"}]}
        self.assertFalse(NativeDocument(d).edges())
        d["relationships"][0]["relationshipType"] = "DEPENDENCY_OF"
        self.assertEqual(NativeDocument(d).edges(), {("b", "a")})

    def test_vendored_occurrences_do_not_confuse_installed_identity(self):
        d = document()
        d["components"].append({"type": "library", "name": "beta", "version": "1", "purl": "pkg:pypi/beta@1",
                                 "bom-ref": "vendor-b", "properties": [{"name": "syft:location:path",
                                     "value": "/site-packages/pip/_vendor/beta/METADATA"}]})
        self.target("Name: alpha\nVersion: 1\nRequires-Dist: beta>=2\n")
        self.target("Name: beta\nVersion: 2\n")
        r = verify(d, self.store, context(), self.facts(d))
        self.assertIn(("a", "b"), NativeDocument(r["document"]).edges())
        self.assertEqual(len(NativeDocument(r["document"]).packages()), 3)
        result = evaluate(document(), d, r["document"])
        self.assertEqual(result["whole_nodes"]["fp"], 0)

    def test_spdx_file_relationships_preserve_installed_scope_without_oracle(self):
        from sbom_recovery.scope import installed_view
        d={"spdxVersion":"SPDX-2.3","packages":[],"files":[],"relationships":[]}
        entries=[("installed","lib/python3.11/site-packages/beta-2.dist-info/METADATA"),
                 ("vendor","lib/python3.11/site-packages/setuptools/_vendor/beta-1.dist-info/METADATA"),
                 ("fixture","lib/python3.11/site-packages/pip/_vendor/tests/data/beta-0.dist-info/METADATA")]
        for ref,path in entries:
            d["packages"].append({"SPDXID":ref,"name":"beta","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:pypi/beta@2"}]})
            d["files"].append({"SPDXID":"file-"+ref,"fileName":path})
            d["relationships"].append({"spdxElementId":ref,"relatedSpdxElement":"file-"+ref,"relationshipType":"CONTAINS"})
        original=deepcopy(d)
        view,audit=installed_view(d)
        self.assertEqual(set(NativeDocument(view).packages()),{"installed"})
        self.assertEqual(d,original)
        self.assertEqual(len(audit["records"]),3)
        # A scanner may combine top-level and nested occurrences in one record.
        d["relationships"].append({"spdxElementId":"installed","relatedSpdxElement":"file-vendor","relationshipType":"CONTAINS"})
        self.assertIn("installed",NativeDocument(installed_view(d)[0]).packages())

    def test_target_metadata_symlink_is_rejected_before_any_bytes_are_hashed(self):
        from sbom_recovery.targets import metadata_inventory
        target=Path(self.tmp.name)/"target"
        directory=target/"lib/site-packages/alpha-1.dist-info"
        directory.mkdir(parents=True)
        outside=Path(self.tmp.name)/"oracle-secret"
        outside.write_text("evaluation-only bytes")
        (directory/"METADATA").symlink_to(outside)
        with patch("sbom_recovery.targets.digest",side_effect=AssertionError("must not open a file")):
            with self.assertRaisesRegex(ValueError,"SYMLINK"):
                metadata_inventory(target)

    def test_relative_capture_paths_bind_to_the_same_frozen_target(self):
        from sbom_recovery.campaign import build_sources
        from sbom_recovery.targets import metadata_inventory
        from sbom_recovery.storage import save
        root=Path(self.tmp.name)/"relative-capture"
        path=root/"runtime/target/lib/site-packages/alpha-1.dist-info/METADATA"
        path.parent.mkdir(parents=True);path.write_text("Name: alpha\nVersion: 1\n")
        _,target_id=metadata_inventory(root/"runtime/target")
        ctx=context().model_copy(update={"target_id":target_id})
        save(root/"capture.json",{"historical_resolution_horizon":ctx.evidence_cutoff})
        previous=Path.cwd()
        try:
            os.chdir(self.tmp.name)
            sources=build_sources("relative-capture",ctx)
        finally:
            os.chdir(previous)
        self.assertEqual(len(sources),1)
        self.assertTrue(Path(next(iter(sources.values()))["path"]).is_absolute())

    def test_reports_keep_conditions_budgets_and_mask_families_separate(self):
        from sbom_recovery.reporting import read_records,aggregate
        from sbom_recovery.storage import save
        root=Path(self.tmp.name)/"report-input"
        rows=[]
        for i,(condition,budget,family,status,value) in enumerate([
                ("fixed",64,"raw","COMPLETE",1.),("active",64,"raw","MODEL_ERROR",0.),
                ("active",16,"raw","COMPLETE",.2),("active",64,"metadata","COMPLETE",.8)]):
            case=root/str(i)
            save(case/"records.json",{"records":[{"project":"alpha","partition":"test","method":"single_agent",
                 "condition":condition,"budget":budget,"family":family,"rate":0 if family=="raw" else .5,
                 "model":"model-a","status":status,"metrics":{"new_metadata_f1":value}}]})
        records,_=read_records(root)
        groups=aggregate(records)
        self.assertEqual(len(groups),4)
        failed=next(r for r in groups if r["condition"]=="active" and r["budget"]==64 and r["family"]=="raw")
        self.assertEqual(failed["incomplete"],1)
        self.assertEqual(failed["new_metadata_f1"],0.)
        self.assertEqual(failed["new_metadata_f1_n_projects"],1)
        self.assertIsNone(failed["vrr_after"])

    def test_unifier_receives_the_same_regenerated_native_sbom_peers(self):
        from sbom_recovery.campaign import sbom_peers
        from sbom_recovery.scope import installed_view
        from sbom_recovery.storage import save
        root=Path(self.tmp.name)/"paired-capture"
        d={"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[
           {"SPDXID":"a","name":"alpha","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:pypi/alpha@1"}]},
           {"SPDXID":"b","name":"beta","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:pypi/beta@2"}]}],
           "relationships":[{"spdxElementId":"a","relatedSpdxElement":"b","relationshipType":"DEPENDS_ON"}]}
        save(root/"runtime/syft.spdx.json",d)
        save(root/"runtime/trivy.spdx.json",d)
        observed,_=controlled_mask(installed_view(d,context().root_purls)[0],1.,11,"dependency")
        peers=sbom_peers(root,observed,context())
        self.assertEqual(peers[0],("input",observed))
        self.assertEqual(len(peers),2)  # Exact duplicate scanner documents are redundant.
        self.assertIn(("a","b"),NativeDocument(peers[1][1]).edges())

    def test_vulnerability_recovery_and_zero_advisory_denominator(self):
        from sbom_recovery.security import vulnerability_recovery
        vrr = vulnerability_recovery({("a","b")}, set(), {("a","b")}, {"a"}, {"b": ["ADVISORY-TEST"]})
        self.assertEqual(vrr["vrr_after"], 1.)
        self.assertEqual(vulnerability_recovery(set(),set(),set(),{"a"},{})["vrr_after"], None)

    def test_model_runner_uses_tool_protocol_and_shared_verifier(self):
        class ReplayGateway:
            def __init__(self):
                self.calls=[]
            def chat(self, model, messages, **kwargs):
                self.calls.append({"usage": {"total_tokens": 1}})
                return {"content": json.dumps({"action": "inspect" if len(self.calls)==1 else "finish", "arguments": {}})}, self.calls[-1]
        broker=ToolBroker(document(),self.store,context())
        result=run_agent(broker,ReplayGateway(),"replay-model",max_turns=3)
        self.assertEqual(result["status"],"COMPLETE")
        self.assertEqual(result["llm_api_calls"],2)
        self.assertEqual(result["verified"]["document"], document())

    def test_tools_cannot_read_paths_or_instructions_and_fail_closed(self):
        broker = ToolBroker(document(), self.store, context(), budget=1)
        with self.assertRaisesRegex(ValueError, "TOOL_NOT_ALLOWED"):
            broker.call("shell", {"cmd": "cat oracle"})
        with self.assertRaisesRegex(ValueError, "BUDGET"):
            broker.call("inspect", {})
        with self.assertRaises(ValueError):
            self.store.read("../../oracle/labels")

    def test_unknown_labels_and_project_bootstrap(self):
        d = document()
        score = evaluate(d, d, d)
        self.assertIsNone(score["new_edges"]["f1"])
        self.assertEqual(score["downstream"]["vrr"], None)
        rows = [{"project": "one", "method": m, "metrics": {"f": v}} for m,v in [("a",1.),("b",0.),("a",1.)]]
        self.assertEqual(paired_bootstrap(rows,"a","b","f",100)["n_projects"],1)
        curve = risk_coverage([{"score": .8,"correct": True},{"score": .1,"correct": None}])
        self.assertEqual(curve["unknown_labels"],1)

    def test_api_credentials_not_in_transcript_and_http_errors_are_redacted(self):
        def handler(request):
            self.assertEqual(request.headers["Authorization"], "Bearer test-secret")
            return httpx.Response(200,json={"data": [],"echo": "test-secret"})
        g = Gateway("test-secret",transport=httpx.MockTransport(handler))
        try:
            result = g.models()
            self.assertNotIn("test-secret",json.dumps(result)+json.dumps(g.calls))
        finally:
            g.close()

    def test_export_preserves_acquisition_time_and_record_binding(self):
        eid=self.target("Name: alpha\nVersion: 1\n")
        original=self.store.manifest()
        exported=Path(self.tmp.name)/"exported"
        self.store.export(exported)
        copied=EvidenceStore(exported)
        try:
            self.assertEqual(copied.manifest(),original)
            self.assertEqual(copied.read(eid)[1],self.store.read(eid)[1])
        finally: copied.close()

    def test_interrupted_blob_is_quarantined_and_restored_from_bound_bytes(self):
        eid=self.target("Name: alpha\nVersion: 1\n")
        before=self.store.manifest()
        record,_=self.store.read(eid)
        blob=Path(self.tmp.name)/"blobs"/record.sha256
        blob.write_bytes(b"")
        self.assertEqual(self.target("Name: alpha\nVersion: 1\n"),eid)
        self.assertEqual(self.store.manifest(),before)
        self.assertTrue(list((blob.parent/"interrupted-artifacts").iterdir()))

    def test_scoring_failure_does_not_overwrite_sealed_prediction_or_repeat_inference(self):
        from sbom_recovery.campaign import run_case
        from sbom_recovery.storage import save
        from sbom_recovery.formats import NativeDocument
        root=Path(self.tmp.name)/"capture"; (root/"runtime/target").mkdir(parents=True)
        ctx=context().model_copy(update={"target_id":sha([])})
        save(root/"context.json",ctx.model_dump())
        save(root/"capture.json",{"status":"COMPLETE","project":{"name":"alpha","version":"1","partition":"development"},
                                  "historical_resolution_horizon":ctx.evidence_cutoff})
        d={"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","dataLicense":"CC0-1.0","name":"test",
           "documentNamespace":"https://example.com/test","creationInfo":{"creators":["Tool: test"],"created":"2026-01-01T00:00:00Z"},
           "packages":[{"SPDXID":ref,"name":name,"versionInfo":version,"downloadLocation":"NOASSERTION","filesAnalyzed":False,
                        "externalRefs":[{"referenceType":"purl","referenceCategory":"PACKAGE-MANAGER","referenceLocator":purl}]}
                       for ref,name,version,purl in (("a","alpha","1","pkg:pypi/alpha@1"),("b","beta","2","pkg:pypi/beta@2"))],
           "relationships":[{"spdxElementId":"a","relatedSpdxElement":"b","relationshipType":"DEPENDS_ON"}]}
        save(root/"runtime/syft.spdx.json",d)
        out=Path(self.tmp.name)/"case"
        with patch("sbom_recovery.campaign.score_after_seal",side_effect=RuntimeError("labels temporarily unavailable")):
            result=run_case(root,out,methods=["single_scanner"],family="dependency",rate=1.)
        self.assertEqual(result["records"][0]["status"],"SCORING_FAILED")
        prediction=out/"single_scanner/prediction.spdx.json"
        committed=prediction.read_bytes()
        self.assertEqual(NativeDocument(json.loads(committed)).edges(),{("a","b")})
        score={"new_edges":{"f1":1.},"whole_edges":{"f1":1.},"new_nodes":{"f1":None},
               "new_metadata":{"f1":None},"whole_metadata":{"f1":1.}}
        with patch("sbom_recovery.campaign.score_after_seal",return_value=score) as scorer:
            resumed=run_case(root,out,methods=["single_scanner"],family="dependency",rate=1.)
        self.assertEqual(scorer.call_count,1)
        self.assertEqual(prediction.read_bytes(),committed)
        self.assertEqual(resumed["records"][0]["llm_api_calls"],0)

    @unittest.skipUnless(os.environ.get("SBOM_TEST_DOCKER")=="1","explicit Docker integration test")
    def test_live_acquisition_is_preserved_after_worker_cleanup_without_credentials(self):
        import subprocess
        from sbom_recovery.isolated import IsolatedBroker
        raw=b"Name: alpha\nVersion: 1\n"
        path=Path(self.tmp.name)/"alpha.METADATA";path.write_bytes(raw)
        source_id=sha("alpha-file")
        source={"kind":"target_metadata","path":str(path),"description":"target:alpha/METADATA",
                "content_binding":sha({"raw_hex":raw.hex()}),"available_at":"2026-10-28T00:00:00Z"}
        with patch.dict(os.environ,{"NETMIND_API_KEY":"must-not-reach-worker"}):
            broker=IsolatedBroker(document(),self.store,context(),8,{source_id:source},True)
        try:
            result=broker.call("acquire",{"source_id":source_id})
            info=json.loads(subprocess.check_output(["docker","inspect",broker.name],text=True))[0]
            self.assertFalse(any(v.startswith("NETMIND_API_KEY=") for v in info["Config"]["Env"]))
        finally: broker.close()
        self.assertEqual(self.store.read(result["evidence_id"])[1],raw)
        self.assertFalse(Path(broker.scratch.name).exists())
        self.assertEqual(broker.audit["final_evidence_sha256"],sha(self.store.manifest()))

    @unittest.skipUnless(os.environ.get("SBOM_TEST_DOCKER")=="1","explicit Docker integration test")
    def test_reference_preparer_and_removal_log_are_not_in_prediction_worker(self):
        import subprocess
        from sbom_recovery.isolated import IsolatedBroker
        broker=IsolatedBroker(document(),self.store,context(),8,{},False)
        try:
            broker.call("inspect",{})
            probe="from pathlib import Path; assert not Path('/code/controlled_reference.py').exists(); assert not Path('/input/mask.json').exists(); assert not Path('/input/oracle').exists()"
            subprocess.run(["docker","exec",broker.name,"python","-c",probe],check=True,capture_output=True)
            self.assertFalse(broker.audit["oracle_mounted"])
            self.assertFalse(broker.audit["key_in_worker"])
        finally:
            broker.close()


if __name__ == "__main__":
    unittest.main()
