"""Synthetic human-response fixtures; never represent actual human review."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from sbom_recovery.gold_pipeline import build_gold
from sbom_recovery.gold_review import export_reviews,check_reviews
from test_gold_proof import make_case


class ReviewTests(unittest.TestCase):
    def fixture(self,root):
        (root/"package.json").write_text('{"name":"demo","version":"1"}')
        case_path,_=make_case(root,[("manifest","package.json","manifest")],"npm")
        build_gold(case_path,root/"gold")
        manifest={"records":[{"case_id":"fixture","status":"COMPLETE_MACHINE_QA","case_path":str(case_path),"gold_path":str(root/"gold")}]}
        (root/"manifest.json").write_text(json.dumps(manifest))
        export_reviews(root/"manifest.json",root/"reviews")
        return root/"reviews"

    def completed(self,review_path,reviewer,verdict="CONFIRMED"):
        data=json.loads(review_path.read_text());data["reviewer_id"]=reviewer;data["independent_human_review_attested"]=True
        for row in data["responses"]:
            row.update(verdict=verdict,notes="SYNTHETIC TEST INPUT ONLY",evidence_source_ids=["manifest"])
        review_path.write_text(json.dumps(data))

    def test_empty_forms_are_pending_and_agreement_undefined(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);review=self.fixture(root)
            result=check_reviews(review/"packet.json",[review/"review-A.json",review/"review-B.json"],root/"check")
            self.assertEqual(result["paired"],0);self.assertIsNone(result["observed_agreement"])
            self.assertFalse(result["ready_for_scale"])
            self.assertFalse(result["labels_modified"])

    def test_export_rejects_changed_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root)
            (root/"package.json").write_text('{"name":"changed","version":"1"}')
            with self.assertRaisesRegex(ValueError,"Changed evidence"):
                export_reviews(root/"manifest.json",root/"second-export")

    def test_discovery_is_separate_and_contains_no_machine_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);review=self.fixture(root)
            claims=json.loads((review/"packet.json").read_text());discovery=json.loads((review/"discovery-packet.json").read_text())
            self.assertTrue(all(t["kind"]!="discovery" for t in claims["tasks"]))
            for task in discovery["tasks"]:
                self.assertNotIn("proposed_value",task)
                self.assertTrue(all(e["kind"] in {"source","manifest","artifact"} for e in task["allowed_evidence"].values()))
            self.assertNotIn("gold_sha256",next(iter(discovery["contexts"].values())))

    def test_same_reviewer_cannot_fill_both_slots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);review=self.fixture(root)
            for slot in ["A","B"]: self.completed(review/("review-"+slot+".json"),"test-same-person")
            with self.assertRaisesRegex(ValueError,"distinct reviewers"):
                check_reviews(review/"packet.json",[review/"review-A.json",review/"review-B.json"],root/"check")

    def test_disagreement_is_queued_and_does_not_change_gold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);review=self.fixture(root);before=(root/"gold/canonical.json").read_bytes()
            self.completed(review/"review-A.json","test-person-a")
            self.completed(review/"review-B.json","test-person-b","INCORRECT")
            result=check_reviews(review/"packet.json",[review/"review-A.json",review/"review-B.json"],root/"check")
            self.assertEqual(result["observed_agreement"],0)
            self.assertTrue(result["disagreements"]);self.assertTrue(result["adjudication_queue"])
            self.assertEqual((root/"gold/canonical.json").read_bytes(),before)

    def test_agreement_does_not_automatically_unlock_scale(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);review=self.fixture(root)
            for slot in ["A","B"]: self.completed(review/("review-"+slot+".json"),"test-person-"+slot)
            result=check_reviews(review/"packet.json",[review/"review-A.json",review/"review-B.json"],root/"check")
            self.assertEqual(result["observed_agreement"],1)
            self.assertFalse(result["ready_for_scale"])

    def test_modified_packet_or_cross_packet_response_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);review=self.fixture(root)
            data=json.loads((review/"review-A.json").read_text());data["packet_sha256"]="a"*64
            (review/"review-A.json").write_text(json.dumps(data))
            with self.assertRaises(ValueError):check_reviews(review/"packet.json",[review/"review-A.json"],root/"check")
            packet=json.loads((review/"packet.json").read_text());packet["tasks"][0]["proposed_value"]="tampered"
            (review/"packet.json").write_text(json.dumps(packet))
            with self.assertRaisesRegex(ValueError,"packet changed"):check_reviews(review/"packet.json",[review/"review-B.json"],root/"check2")

    def test_attestation_and_actual_evidence_are_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);review=self.fixture(root)
            data=json.loads((review/"review-A.json").read_text());data["responses"][0]["verdict"]="CONFIRMED"
            (review/"review-A.json").write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,"human attestation"):check_reviews(review/"packet.json",[review/"review-A.json"],root/"check")
            self.completed(review/"review-A.json","test-person-a")
            data=json.loads((review/"review-A.json").read_text());data["responses"][0]["evidence_source_ids"]=["invented"]
            (review/"review-A.json").write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,"Unknown evidence"):check_reviews(review/"packet.json",[review/"review-A.json"],root/"check2")
