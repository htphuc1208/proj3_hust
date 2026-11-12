"""End-to-end acquisition, proposal gates, resource limits and live HTTP contract."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import httpx

from sbom_recovery.investigation.demo import create_demo
from sbom_recovery.investigation.models import Action, Budget
from sbom_recovery.investigation.planner import GatewayPlanner, PlanningError, ReplayPlanner
from sbom_recovery.investigation.runner import investigate, save_run
from sbom_recovery.investigation.validator import validate_proposals


class InvestigationRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        create_demo(self.root / "demo")
        self.bundle = self.root / "demo/npm"
        self.request = json.loads((self.bundle / "request.json").read_text())

    def run_case(self, **kwargs):
        return investigate(self.request, self.bundle, **kwargs)

    def test_rule_reads_wrong_context_then_reconciles_correct_release(self):
        run = self.run_case()
        self.assertEqual([r["status"] for r in run["acquired"]], ["ERROR", "OK"])
        lib = next(c for c in run["prediction"]["components"] if c["name"] == "example-lib")
        self.assertEqual((lib["version"], lib["status"]), ("1.4.3", "SUPPORTED"))
        self.assertEqual(run["prediction"]["investigation"]["usage"]["tool_calls"], 2)
        self.assertFalse(run["prediction"]["investigation"]["oracle_access"])

    def test_budget_exhaustion_preserves_unknown_instead_of_wrong_winner(self):
        run = self.run_case(budget=Budget(max_tool_calls=1))
        self.assertEqual(run["prediction"]["status"], "RESOURCE_LIMIT")
        self.assertTrue(all(c["status"] == "UNKNOWN" for c in run["prediction"]["components"]))
        self.assertEqual(len(run["tool_trace"]), 1)

    def test_invalid_and_repeated_model_actions_are_charged(self):
        actions = [{"action": "shell", "source_id": "oracle"},
                   {"action": "acquire", "source_id": "not-allowed"},
                   {"action": "acquire", "source_id": "not-allowed"}, {"action": "finish"}]
        run = self.run_case(policy="agent", planner=ReplayPlanner(actions), budget=Budget(max_tool_calls=3))
        self.assertEqual(len(run["tool_trace"]), 3)
        self.assertTrue(all(r["response"]["status"] == "ERROR" for r in run["tool_trace"]))
        self.assertEqual(run["prediction"]["investigation"]["planner_kind"], "RECORDED_ACTION_REPLAY")

    def test_replay_adapts_to_error_and_cannot_invent_supported_claims(self):
        actions = json.loads((self.bundle / "actions.json").read_text())
        actions[-1]["proposals"] = [{"claim_id": "invented", "evidence_ids": ["01-resolution"]}]
        run = self.run_case(policy="agent", planner=ReplayPlanner(actions))
        self.assertEqual(run["prediction"]["proposal_validation"]["rejected"], 1)
        self.assertEqual(len(run["prediction"]["components"]), 2)
        self.assertEqual(run["tool_trace"][1]["previous_sha256"], run["tool_trace"][0]["sha256"])

    def test_fixed_evidence_agent_cannot_acquire_more_information(self):
        acquired = self.run_case()["acquired"]
        run = self.run_case(policy="fixed_llm", initial_evidence=acquired,
            planner=ReplayPlanner([{"action": "acquire", "source_id": "01-resolution"}, {"action": "finish"}]))
        self.assertEqual(run["tool_trace"][0]["response"]["status"], "ERROR")
        self.assertTrue(run["prediction"]["investigation"]["fixed_evidence"])
        self.assertEqual(run["acquired"], acquired)

    def test_model_call_limit_applies_even_to_replays(self):
        run = self.run_case(policy="agent", planner=ReplayPlanner([]), budget=Budget(max_model_calls=0))
        self.assertEqual(run["prediction"]["status"], "MODEL_CALL_LIMIT")

    def test_equal_information_rule_cannot_acquire_hidden_sources(self):
        run = self.run_case(policy="rule", fixed_evidence=True, initial_evidence=[])
        self.assertEqual(run["tool_trace"], [])
        self.assertTrue(all(c["status"] == "UNKNOWN" for c in run["prediction"]["components"]))

    def test_saved_outputs_validate_and_seal_actual_artifact_bytes(self):
        run = self.run_case()
        snapshot = json.loads((self.bundle / "advisories.json").read_text())
        save_run(run, self.root / "run", snapshot=snapshot)
        seal = json.loads((self.root / "run/seal.json").read_text())
        for name, expected in seal["files"].items():
            self.assertEqual(hashlib.sha256((self.root / "run" / name).read_bytes()).hexdigest(), expected)
        self.assertIn("security", json.loads((self.root / "run/prediction.json").read_text()))
        with self.assertRaises(FileExistsError):
            save_run(run, self.root / "run")

    def test_proposal_evidence_must_support_exact_claim(self):
        result = {"claims": [{"claim_id": "v", "status": "SUPPORTED", "support_evidence_ids": ["right"]}]}
        acquired = [{"source_id": "right", "status": "OK"}, {"source_id": "irrelevant", "status": "OK"}]
        result = validate_proposals(result, [{"claim_id": "v", "evidence_ids": ["irrelevant"]}], acquired)
        self.assertEqual(result["rejected"], 1)

    def test_cargo_smoke_has_corrected_identity_and_runtime_path(self):
        bundle = self.root / "demo/cargo"
        run = investigate(json.loads((bundle / "request.json").read_text()), bundle)
        self.assertEqual(len(run["prediction"]["components"]), 2)
        self.assertTrue(any(e["status"] == "SUPPORTED" for e in run["prediction"]["edges"]))

    def test_cve_triggered_agent_can_match_frozen_advisory_before_and_after_evidence(self):
        snapshot = json.loads((self.bundle / "advisories.json").read_text())
        actions = [{"action": "match_advisories"}, {"action": "acquire", "source_id": "01-resolution"},
                   {"action": "match_advisories"}, {"action": "finish"}]
        run = self.run_case(policy="agent", planner=ReplayPlanner(actions), advisory_snapshot=snapshot,
                            advisory_ids=["CVE-DEMO-001"])
        before = run["tool_trace"][0]["response"]["assessment"]["findings"]
        after = run["tool_trace"][2]["response"]["assessment"]["findings"]
        self.assertTrue(any(f["status"] == "POTENTIALLY_AFFECTED" for f in before))
        self.assertEqual(after[0]["status"], "NOT_IN_AFFECTED_RANGE")
        self.assertEqual(run["prediction"]["investigation"]["focused_advisory_ids"], ["CVE-DEMO-001"])

    def test_raw_artifact_hash_does_not_create_verified_packages(self):
        raw = b"controlled artifact bytes\x00\xff"
        digest = hashlib.sha256(raw).hexdigest()
        (self.bundle / "artifact.bin").write_bytes(raw)
        self.request["evidence"] = [{"source_id": "artifact-hash", "kind": "artifact_bytes",
            "blob": {"path": "artifact.bin", "sha256": digest}}]
        self.request["target"]["artifact"] = {"kind": "native_binary",
            "artifact": {"path": "artifact.bin", "sha256": digest}}
        run = self.run_case()
        self.assertEqual(run["acquired"][0]["artifact_digest"]["binding"], "DIRECT_ARTIFACT")
        self.assertEqual(run["acquired"][0]["artifact_digest"]["value"], digest)
        self.assertTrue(all(c["status"] == "UNKNOWN" for c in run["prediction"]["components"]))

    def test_agent_view_is_compact_and_native_observations_are_targeted(self):
        from sbom_recovery.investigation.broker import Broker
        from sbom_recovery.investigation.engine import ingest
        from sbom_recovery.investigation.evidence import EvidenceCatalog
        from sbom_recovery.reconciliation.merge_contracts_v3 import ReconciliationRequestV3
        request = ReconciliationRequestV3.model_validate(self.request)
        broker = Broker(ingest(request, self.bundle), EvidenceCatalog(request, self.bundle))
        view = broker.view()
        self.assertNotIn("source_documents", view["assessment"])
        self.assertNotIn("raw_observations", view["assessment"])
        subject = view["assessment"]["components"][0]["id"]
        response = broker.call({"action": "inspect", "subject_id": subject})
        self.assertEqual(response["status"], "OK")
        self.assertTrue(response["inspection"]["observations"])
        self.assertEqual(broker.remaining()["tool_calls"], 9)
        self.assertGreater(broker.bytes_used, 0)
        self.assertEqual(broker.call({"action": "inspect", "subject_id": "oracle/oracle.json"})["status"], "ERROR")


class GatewayPlannerTests(unittest.TestCase):
    def budget(self, **kwargs):
        return Budget(input_usd_per_million=0.1, output_usd_per_million=0.2, **kwargs)

    def planner(self, handler):
        planner = GatewayPlanner("frozen-model-v1", key="fixture-secret", transport=httpx.MockTransport(handler))
        self.addCleanup(planner.close)
        return planner

    def test_live_http_contract_is_single_step_without_secret_in_records(self):
        requests = []
        def handler(request):
            requests.append(json.loads(request.content))
            return httpx.Response(200, json={"choices": [{"message": {"content": '{"action":"finish"}'}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 10}, "system_fingerprint": "fixture-secret"})
        planner = self.planner(handler)
        self.assertEqual(planner.next_action({"content_role": "UNTRUSTED_DATA"}, self.budget(), 3)["action"], "finish")
        self.assertEqual(len(requests), 1)
        self.assertEqual(planner.tokens, 110)
        self.assertNotIn("fixture-secret", json.dumps(planner.records))

    def test_no_usage_or_http_failure_never_retries_or_exceeds_reserved_budget(self):
        calls = []
        def handler(request):
            calls.append(request)
            return httpx.Response(500, text="fixture-secret should never be journaled")
        planner = self.planner(handler)
        with self.assertRaisesRegex(PlanningError, "MODEL_HTTP_500"):
            planner.next_action({}, self.budget(), 3)
        self.assertEqual(len(calls), 1)
        self.assertEqual(planner.records[0]["usage_kind"], "RESERVED_UNKNOWN_USAGE")
        self.assertNotIn("fixture-secret", json.dumps(planner.records))

    def test_missing_frozen_prices_refuses_live_request(self):
        planner = self.planner(lambda r: self.fail("HTTP must not be called"))
        with self.assertRaisesRegex(PlanningError, "prices"):
            planner.next_action({}, Budget(), 3)

    def test_token_reservation_refuses_oversized_context_before_http(self):
        planner = self.planner(lambda r: self.fail("HTTP must not be called"))
        with self.assertRaisesRegex(PlanningError, "BUDGET"):
            planner.next_action({"content": "x" * 10000}, self.budget(max_tokens=1000), 3)

    def test_strict_actions_and_budget_reject_unbounded_inputs(self):
        for args in ({"max_steps": -1}, {"max_seconds": float("inf")}, {"max_tool_calls": True}):
            with self.assertRaises(ValueError):
                Budget(**args)
        with self.assertRaises(ValueError):
            Action.model_validate({"action": "acquire", "source_id": "x", "command": "cat oracle"})
