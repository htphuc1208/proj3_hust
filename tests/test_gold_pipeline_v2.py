"""Synthetic regression controls, not empirical recovery benchmarks."""
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
import subprocess
from pathlib import Path

from sbom_recovery.canonical import CanonicalClaim, CanonicalLedger, EvidenceItem, VerificationRecord
from sbom_recovery.gold_contracts import CaseManifest, ClaimV2, LedgerV2, FrozenFile
from sbom_recovery.gold_pipeline import build_gold, validate_gold, Builder
from sbom_recovery.gold_pilot import run_e1,observations
from sbom_recovery.claim_scorer import ClaimScorer
from sbom_recovery.acquisition_tools import EvidenceToolCatalog, BudgetedScheduler
from sbom_recovery.e1_experiment import E1DecisionEngine
from sbom_recovery.native_graph import normalize


class GoldV2Tests(unittest.TestCase):
    def claim(self, **kwargs):
        return CanonicalClaim(case_id="case",subject="pkg:pypi/a@1",predicate="version",object="1",**kwargs)

    def score(self,gold,pred):
        return ClaimScorer.evaluate_case("case","test",CanonicalLedger(case_id="case",claims=gold),
            CanonicalLedger(case_id="case"),CanonicalLedger(case_id="case",claims=pred))

    def test_no_cross_layer_or_scope_matches(self):
        report=self.score([self.claim(layer="G2_resolved")],[self.claim(layer="G1_source")])
        self.assertEqual(report.overall_metrics.tp,0)
        self.assertEqual(report.unjudged_assertions,1)
        self.assertEqual(self.score([self.claim(scope="test")],[self.claim()]).overall_metrics.tp,0)

    def test_unknown_and_incomplete_gold_are_not_negatives(self):
        for gold in [[],[self.claim(status="unknown")],[self.claim(status="not_applicable")]]:
            report=self.score(gold,[self.claim()])
            self.assertEqual(report.overall_metrics.fp,0)
            self.assertEqual(report.unjudged_assertions,1)
            self.assertIsNone(report.far)

    def test_proven_absence_is_negative(self):
        report=self.score([self.claim(status="verified_absent")],[self.claim()])
        self.assertEqual(report.overall_metrics.fp,1)

    def test_fingerprint_binds_evidence(self):
        a=CanonicalLedger(case_id="case",claims=[self.claim()])
        b=CanonicalLedger.model_validate(a.model_dump())
        b.claims[0].evidence.append(EvidenceItem(source_id="new",source_type="manifest_source",locator="here"))
        self.assertNotEqual(a.fingerprint(),b.fingerprint())

    def test_gold_cannot_be_scanner_or_model_verified(self):
        values=dict(case_id="case",target_id=".",instance_id="root",subject="pkg:pypi/a",predicate="version",object="1",role="gold",status="verified")
        with self.assertRaises(ValueError): ClaimV2(**values)
        with self.assertRaises(ValueError): ClaimV2(**values,evidence=[EvidenceItem(source_id="syft",source_type="scanner_sbom",artifact_sha256="a"*64,locator="pkg")])

    def test_multivalued_dependencies_survive_voting(self):
        claims=[CanonicalClaim(case_id="case",subject="root",predicate="depends_on",object=n,
            evidence=[EvidenceItem(source_id=t,source_type="scanner_sbom",locator=n) for t in ["syft","trivy"]]) for n in ["a","b"]]
        result=E1DecisionEngine.resolve_b1_majority(CanonicalLedger(case_id="case",claims=claims))
        self.assertEqual(len(result.resolved_ledger.claims),2)

    def test_budget_bounds_and_denied_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/"uv.lock").write_text("0123456789")
            (root/"oracle").mkdir(); (root/"oracle"/"labels.json").write_text("secret labels")
            (root/"link").symlink_to(root/"uv.lock")
            catalog=EvidenceToolCatalog(root,allowed_files={"ok":"uv.lock","bad":"oracle/labels.json","link":"link","escape":"../outside"})
            for key in ["bad","link","escape","/etc/passwd"]:
                result,size=catalog.read_lockfile(key)
                self.assertIn("error",result); self.assertEqual(size,0)
            scheduler=BudgetedScheduler(catalog,max_actions=2,max_bytes=3)
            result=scheduler.execute_action("read_lockfile",lockfile_name="ok")
            self.assertEqual(result["content"],"012"); self.assertTrue(result["truncated"])
            self.assertEqual(scheduler.bytes_used,3)
            self.assertIn("error",scheduler.execute_action("read_lockfile",lockfile_name="ok"))

    def test_invalid_calls_charge_actions(self):
        scheduler=BudgetedScheduler(EvidenceToolCatalog(),max_actions=1)
        self.assertIn("error",scheduler.execute_action("__dict__"))
        self.assertEqual(scheduler.actions_used,1)

    def test_catalog_rejects_changes_after_freeze(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"uv.lock";path.write_text("original")
            catalog=EvidenceToolCatalog(tmp)
            path.write_text("changed")
            result,size=catalog.read_lockfile("uv.lock")
            self.assertIn("error",result)
            self.assertEqual(size,0)

    def fixture(self,root):
        manifest=root/"pom.xml"
        manifest.write_text('<project><groupId>org.demo</groupId><artifactId>demo</artifactId><version>1</version></project>')
        raw={"groupId":"org.demo","artifactId":"demo","version":"1","children":[
            {"groupId":"org.demo","artifactId":"lib","version":"2","scope":"runtime"},
            {"groupId":"org.demo","artifactId":"test-lib","version":"3","scope":"test"}]}
        (root/"raw.json").write_text(json.dumps(raw))
        env={"os":"linux","arch":"x86_64","runtime":"fixture-jdk17"}
        nodes,edges=normalize("maven",raw,"demo")
        report={"status":"COMPLETE","commit":"a"*40,"target":".","environment":env,
                "nodes":nodes,"edges":edges,"raw_evidence_id":"raw","root_name":"demo"}
        (root/"resolved.json").write_text(json.dumps(report))
        files={key:FrozenFile(path=name,sha256=hashlib.sha256((root/name).read_bytes()).hexdigest(),kind=kind)
               for key,name,kind in [("manifest","pom.xml","manifest"),("raw","raw.json","resolver"),("resolved","resolved.json","resolver")]}
        case=CaseManifest(case_id="fixture",repository="https://example.invalid/demo",commit="a"*40,ecosystem="maven",
            environment=env,evidence_cutoff="2026-11-02T00:00:00Z",files=files,allowed_evidence=list(files),resolution_status="COMPLETE")
        (root/"case.json").write_text(case.model_dump_json())
        return root/"case.json",case

    def test_pipeline_and_native_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); path,case=self.fixture(root)
            result=build_gold(path,root/"out")
            self.assertEqual(result["status"],"PASSED")
            self.assertIn("G2_resolved",result["layers"])
            self.assertEqual(json.loads((root/"out/native-validation.json").read_text())["spdx"]["valid"],True)
            self.assertNotIn("test-lib",(root/"out/gold.cdx.json").read_text())
            summary=run_e1(path,root/"e1",isolated=False)
            self.assertEqual(summary["llm_api_calls"],0)
            self.assertEqual(len(summary["scores"]),3)
            with self.assertRaises(FileExistsError): build_gold(path,root/"out")

    def test_timed_out_worker_is_stopped_and_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path,_=self.fixture(root)
            timeout=subprocess.TimeoutExpired(["docker","run"],120)
            with patch("sbom_recovery.gold_pilot.subprocess.check_output",return_value="sha256:fixture"), patch(
                    "sbom_recovery.gold_pilot.subprocess.run",side_effect=[timeout,subprocess.CompletedProcess([],0)]) as execute:
                with self.assertRaisesRegex(RuntimeError,"timed out"): run_e1(path,root/"out")
            self.assertEqual(execute.call_args_list[1].args[0][:4],["docker","stop","-t","2"])
            self.assertEqual(json.loads((root/"out/worker-boundary.json").read_text())["status"],"TIMEOUT")

    def test_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); path,case=self.fixture(root)
            builder=Builder(path); gold=builder.build()
            gold.claims[0].evidence[0].locator="invented"
            with self.assertRaises(ValueError): validate_gold(path,gold)
            (root/"pom.xml").write_text("changed")
            with self.assertRaises(ValueError): Builder(path)

    def test_gold_status_cannot_be_downgraded_to_hide_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path,_=self.fixture(root)
            gold=Builder(path).build()
            gold.claims[0].status="unknown"
            with self.assertRaises(ValueError): validate_gold(path,gold)

    def test_context_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); path,case=self.fixture(root)
            case.environment["arch"]="arm64"
            path.write_text(case.model_dump_json())
            with self.assertRaises(ValueError): Builder(path).build()

    def test_prediction_preparation_never_reads_disallowed_native_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path,case=self.fixture(root)
            case.allowed_evidence=["manifest"]
            path.write_text(case.model_dump_json())
            (root/"raw.json").unlink()
            initial,evidence=observations(path)
            self.assertTrue(evidence.claims)
            self.assertTrue(all(e.source_id=="manifest" for c in evidence.claims for e in c.evidence))

    def test_marker_context_never_falls_back_to_host(self):
        raw={"environment":{},"installed":[{"metadata":{"name":"a","version":"1","requires_dist":['b; python_version >= "3"']}}]}
        with self.assertRaisesRegex(ValueError,"Context-Uncertain"): normalize("pypi",raw,"a")

    def test_npm_scoped_names_and_workspace_instances(self):
        from sbom_recovery.gold_pipeline import purl
        self.assertEqual(purl("npm","@org/pkg","1"),"pkg:npm/%40org/pkg@1")
        raw={"name":"root","version":"1","dependencies":{"@org/a":{"version":"2","dependencies":{"x":{"version":"1"}}},"b":{"version":"2","dependencies":{"x":{"version":"2"}}}}}
        nodes,edges=normalize("npm",raw,"root")
        self.assertEqual(len([n for n in nodes if n["name"]=="x"]),2)

    def test_python_inactive_markers_and_transitive_extras(self):
        raw={"environment":{"sys_platform":"linux"},"installed":[
            {"metadata":{"name":"a","version":"1","requires_dist":["b[security]",'windows-only; sys_platform == "win32"']}},
            {"metadata":{"name":"b","version":"1","requires_dist":['c; extra == "security"']}},
            {"metadata":{"name":"c","version":"1"}}]}
        nodes,edges=normalize("pypi",raw,"a")
        self.assertEqual({n["name"] for n in nodes},{"a","b","c"})
        self.assertIn(("b","c"),edges)


if __name__=="__main__": unittest.main()
