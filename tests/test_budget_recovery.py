"""Synthetic boundary controls: no model-quality or security-effectiveness claim."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from sbom_recovery.budget_agent import BudgetBroker, run_control, run_budget_agent
from sbom_recovery.budget_sources import prepare_catalog, TrustedReader
from sbom_recovery.candidate_risk import assess_risk
from sbom_recovery.formats import NativeDocument, sha
from sbom_recovery.targets import metadata_inventory
from sbom_recovery.llm import GatewayError
from unittest.mock import patch
from tests.test_agent_recovery import document, context


class BudgetRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.target = Path(self.temp.name) / "target"
        self.doc = document()
        self.doc["components"].append({"type":"library","name":"gamma","version":"3","purl":"pkg:pypi/gamma@3","bom-ref":"c"})
        self.doc["dependencies"] = [{"ref":"b","dependsOn":["c"]}]
        self.put("alpha","1","Requires-Dist: beta>=2\n")
        self.put("beta","2",'Requires-Dist: gamma; extra == "optional"\n')
        self.put("gamma","3","")
        self.put("unrelated","1","")

    def put(self,name,version,requires):
        path=self.target/f"lib/python3.11/site-packages/{name}-{version}.dist-info/METADATA"
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n{requires}\n")

    def setup_broker(self,budget=4,byte_budget=2097152,max_tools=128):
        self.ctx=context().model_copy(update={"target_id":metadata_inventory(self.target)[1]})
        self.catalog=prepare_catalog(self.target,self.ctx,"2026-10-28T00:00:00Z")
        self.reader=TrustedReader(self.target,self.catalog,self.ctx)
        self.ids={s["name_hint"]:s["source_id"] for s in self.catalog["sources"]}
        return BudgetBroker(self.doc,self.ctx,self.catalog,self.reader.read,budget=budget,byte_budget=byte_budget,max_tools=max_tools)

    def acquire(self,broker,*names):
        for name in names:broker.call("acquire",{"source_id":self.ids[name]})

    def test_initial_inspect_and_assess_never_read_source_contents(self):
        broker=self.setup_broker()
        self.assertEqual(self.reader.attempts,[])
        broker.call("inspect",{});result=broker.call("assess",{})
        self.assertEqual(self.reader.attempts,[])
        self.assertFalse(result["complete_acquired_catalog"])
        self.assertFalse(result["proposals"])
        self.assertTrue(all("requirements" not in row and "content" not in row for row in broker.state()["catalog"]["sources"]))

    def test_invalid_and_duplicate_attempts_consume_acquisition_budget(self):
        broker=self.setup_broker(budget=3)
        with self.assertRaises(ValueError):broker.call("acquire",{"source_id":"unknown"})
        self.acquire(broker,"alpha")
        with self.assertRaises(ValueError):self.acquire(broker,"alpha")
        self.assertEqual(broker.attempts,3)
        with self.assertRaisesRegex(ValueError,"BUDGET"):self.acquire(broker,"beta")
        self.assertEqual(len(self.reader.attempts),1)

    def test_partial_source_reads_cannot_close_optional_extras(self):
        broker=self.setup_broker(budget=2)
        self.acquire(broker,"beta","gamma")
        result=broker.call("finish",{})
        self.assertFalse(result["retracted_edges"])
        self.assertIn(("b","c"),NativeDocument(result["document"]).edges())
        self.assertEqual(result["assessment_counts"],{"UNKNOWN":1})

    def test_partial_evidence_can_retract_context_independent_inactive_marker(self):
        self.put("beta","2",'Requires-Dist: gamma; sys_platform == "win32"\n')
        broker=self.setup_broker(budget=2)
        self.acquire(broker,"beta","gamma")
        self.assertEqual(broker.finalize()["retracted_edges"],[["b","c"]])

    def test_full_acquisition_recovers_missing_edge_and_reconciles_inactive_extra(self):
        broker=self.setup_broker()
        original=deepcopy(self.doc)
        self.acquire(broker,"alpha","beta","gamma","unrelated")
        result=broker.finalize()
        self.assertEqual(NativeDocument(result["document"]).edges(),{("a","b")})
        self.assertEqual(self.doc,original)
        self.assertTrue(result["complete_acquired_catalog"])
        self.assertTrue(result["validation"]["valid"])

    def test_known_transitive_extra_prevents_false_retraction(self):
        self.put("alpha","1","Requires-Dist: beta[optional]>=2\n")
        broker=self.setup_broker()
        self.acquire(broker,"alpha","beta","gamma","unrelated")
        self.assertFalse(broker.finalize()["retracted_edges"])

    def test_unknown_transitive_marker_remains_possible_at_full_budget(self):
        self.put("alpha","1",'Requires-Dist: beta[optional]; implementation_name == "pypy"\n')
        broker=self.setup_broker()
        self.acquire(broker,"alpha","beta","gamma","unrelated")
        self.assertFalse(broker.finalize()["retracted_edges"])

    def test_installed_dynamic_field_is_informational_not_global_abstention(self):
        self.put("unrelated","1","Dynamic: Requires-Dist\n")
        broker=self.setup_broker()
        self.acquire(broker,"alpha","beta","gamma","unrelated")
        self.assertEqual(broker.finalize()["retracted_edges"],[["b","c"]])

    def test_runtime_incompatible_metadata_abstains(self):
        self.put("beta","2","Requires-Python: >=3.12\nRequires-Dist: gamma\n")
        broker=self.setup_broker();self.acquire(broker,"alpha","beta")
        result=broker.finalize()
        self.assertFalse(result["proposals"])
        self.assertTrue(result["diagnostics"])

    def test_acquisition_feedback_is_derived_only_from_acquired_bytes(self):
        broker=self.setup_broker(budget=1)
        value=broker.call("acquire",{"source_id":self.ids["alpha"]})
        self.assertIn("beta",value["recovery_state"]["frontier_names"])
        self.assertEqual(len(self.reader.attempts),1)
        self.assertEqual(broker.state()["max_source_bytes"],262144)

    def test_vendored_occurrence_does_not_confuse_installed_identity(self):
        self.doc["components"].append({"type":"library","name":"beta","version":"2","purl":"pkg:pypi/beta@2",
            "bom-ref":"vendor-beta","properties":[{"name":"syft:location:path","value":"/site-packages/pip/_vendor/beta/METADATA"}]})
        self.doc["dependencies"].append({"ref":"vendor-beta","dependsOn":["c"]})
        broker=self.setup_broker();self.acquire(broker,"alpha","beta","gamma","unrelated")
        result=broker.finalize()
        self.assertIn(("a","b"),NativeDocument(result["document"]).edges())
        self.assertIn(("vendor-beta","c"),NativeDocument(result["document"]).edges())
        self.assertNotIn(["vendor-beta","c"],result["retracted_edges"])

    def test_malformed_model_protocol_fails_closed_with_prediction(self):
        for message in [None,{}, {"tool_calls":"invalid"},{"tool_calls":["invalid"]}]:
            broker=self.setup_broker()
            class BadGateway:
                calls=[]
                def chat(self,*args,**kwargs):return message,{"usage":None}
            result=run_budget_agent(broker,BadGateway(),"mock")
            self.assertEqual(result["status"],"MODEL_PROTOCOL_ERROR")
            self.assertEqual(result["result"]["document"],self.doc)

    def test_sdist_and_changed_catalog_rejected(self):
        self.setup_broker()
        catalog=deepcopy(self.catalog);catalog["sources"][0]["kind"]="sdist_metadata"
        catalog["sha256"]=sha({k:v for k,v in catalog.items() if k!="sha256"})
        with self.assertRaises(ValueError):BudgetBroker(self.doc,self.ctx,catalog,self.reader.read)
        catalog=deepcopy(self.catalog);catalog["sources"][0]["bytes"]+=1
        with self.assertRaises(ValueError):BudgetBroker(self.doc,self.ctx,catalog,self.reader.read)

    def test_changed_bytes_symlinks_and_oversize_fail_closed(self):
        broker=self.setup_broker(byte_budget=1)
        with self.assertRaisesRegex(ValueError,"ALLOWANCE"):self.acquire(broker,"alpha")
        self.assertFalse(self.reader.attempts)
        broker=self.setup_broker()
        self.put("alpha","1","Requires-Dist: evil\n")
        with self.assertRaises(ValueError):self.acquire(broker,"alpha")
        self.assertFalse(broker.acquired)
        p=self.target/next(s["path"] for s in self.catalog["sources"] if s["name_hint"]=="beta")
        p.unlink();p.symlink_to(self.target/next(s["path"] for s in self.catalog["sources"] if s["name_hint"]=="gamma"))
        with self.assertRaises(ValueError):self.acquire(broker,"beta")

    def test_exhausted_tool_budget_still_allows_failure_finalize(self):
        broker=self.setup_broker(max_tools=0)
        with self.assertRaises(ValueError):broker.call("inspect",{})
        self.assertEqual(broker.finalize()["document"],self.doc)

    def test_all_deterministic_controls_use_same_broker_and_budgets(self):
        for method in ["fixed_order","cheapest_source","unresolved_priority"]:
            broker=self.setup_broker(budget=2)
            result=run_control(broker,method)
            self.assertEqual(result["status"],"COMPLETE")
            self.assertEqual(broker.attempts,2)
            self.assertEqual(len(self.reader.attempts),2)

    def test_mock_model_only_selects_sources_gate_owns_graph_changes(self):
        broker=self.setup_broker(budget=2)
        ids=self.ids
        class MockGateway:
            def __init__(self):self.calls=[]
            def chat(self,*args,**kwargs):
                names=[("acquire",{"source_id":ids["alpha"]}),("acquire",{"source_id":ids["beta"]}),("finish",{})]
                name,arguments=names[len(self.calls)]
                self.calls.append({"usage":None})
                import json
                return {"tool_calls":[{"id":str(len(self.calls)),"type":"function","function":{"name":name,"arguments":json.dumps(arguments)}}]},self.calls[-1]
        result=run_budget_agent(broker,MockGateway(),"mock")
        self.assertEqual(result["status"],"COMPLETE")
        self.assertEqual(result["llm_api_calls"],3)
        self.assertIn(("a","b"),NativeDocument(result["result"]["document"]).edges())
        self.assertIn(("b","c"),NativeDocument(result["result"]["document"]).edges())

    def test_model_error_does_not_erase_acquired_prediction(self):
        broker=self.setup_broker(budget=2)
        self.acquire(broker,"alpha","beta")
        class BrokenGateway:
            calls=[]
            def chat(self,*args,**kwargs):raise RuntimeError("never export secret provider body")
        result=run_budget_agent(broker,BrokenGateway(),"mock")
        self.assertEqual(result["status"],"MODEL_ERROR")
        self.assertNotIn("secret",str(result["transcript"]))
        self.assertIn(("a","b"),NativeDocument(result["result"]["document"]).edges())

    def unrestricted_broker(self):
        self.setup_broker()
        return BudgetBroker(self.doc,self.ctx,self.catalog,self.reader.read,
                            budget=None,byte_budget=None,max_tools=None,max_source_bytes=None)

    def test_unrestricted_mode_exceeds_previous_tool_and_byte_quotas(self):
        self.put('unrelated','1','\n'+'x'*(3*1024*1024))
        broker=self.unrestricted_broker()
        for _ in range(140):broker.call('inspect',{})
        self.acquire(broker,'unrelated','alpha','beta','gamma')
        result=broker.call('finish',{})
        self.assertTrue(result['validation']['valid'])
        self.assertGreater(broker.bytes_read,2097152)
        self.assertIsNone(broker.state()['remaining'])
        self.assertIsNone(broker.state()['max_source_bytes'])

    def test_unrestricted_finish_requires_every_source_to_be_accounted_for(self):
        broker=self.unrestricted_broker()
        with self.assertRaisesRegex(ValueError,'COLLECTION_INCOMPLETE'):broker.call('finish',{})
        self.acquire(broker,'alpha','beta','gamma','unrelated')
        self.assertTrue(broker.call('finish',{})['complete_acquired_catalog'])

    def test_unrestricted_agent_continues_after_32_turns_and_retries_transient_error(self):
        broker=self.unrestricted_broker();ids=list(self.ids.values())
        class ContinuingGateway:
            def __init__(self):self.calls=[];self.attempts=0
            def chat(inner,*args,**kwargs):
                import json
                inner.attempts+=1
                self.assertIsNone(kwargs['max_tokens'])
                if inner.attempts==1:raise GatewayError('temporary',retryable=True)
                i=len(inner.calls);inner.calls.append({})
                if i<40:name,arguments='inspect',{}
                elif i<44:name,arguments='acquire',{'source_id':ids[i-40]}
                else:name,arguments='finish',{}
                return {'tool_calls':[{'id':str(i),'function':{'name':name,'arguments':json.dumps(arguments)}}]},{}
        gateway=ContinuingGateway();checkpoints=[]
        with patch('sbom_recovery.budget_agent.time.sleep'):
            result=run_budget_agent(broker,gateway,'mock',checkpoint=checkpoints.append)
        self.assertEqual(result['status'],'COMPLETE')
        self.assertEqual(len(gateway.calls),45)
        self.assertTrue(checkpoints)
        self.assertEqual(len(broker.acquired),4)


class CandidateRiskTests(unittest.TestCase):
    def test_removing_a_path_cannot_clear_existing_advisory(self):
        before=document();before["dependencies"]=[{"ref":"a","dependsOn":["b"]}]
        after=deepcopy(before);after["dependencies"]=[]
        snapshot={"records":[{"purl":"pkg:pypi/beta@2","advisory_ids":["SYNTHETIC-ADVISORY"]}]}
        result=assess_risk(before,after,["pkg:pypi/alpha@1"],snapshot)
        advisory=next(r for r in result["records"] if r["advisory_id"])
        self.assertEqual(advisory["path_status"],"OBSERVED_DECLARED_PATH")
        self.assertEqual(advisory["openvex_status"],"under_investigation")
        self.assertEqual(advisory["exploitability"],"UNKNOWN")
        self.assertTrue(advisory["changed_path_requires_review"])

    def test_missing_path_and_unqueried_package_stay_unknown(self):
        result=assess_risk(document(),document(),["pkg:pypi/alpha@1"],{"records":[]})
        beta=next(r for r in result["records"] if r["purl"]=="pkg:pypi/beta@2")
        self.assertEqual(beta["path_status"],"UNKNOWN")
        self.assertEqual(beta["advisory_lookup"],"UNKNOWN_NOT_QUERIED")


if __name__ == "__main__":unittest.main()
