"""Blinded evidence packets and honest paired human-review accounting.

This module never edits canonical labels or feeds annotation decisions to inference.
Identity/independence are reviewer attestations, not authenticated proof of identity.
"""
from __future__ import annotations

import json
import random
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .gold_contracts import CaseManifest, LedgerV2, fingerprint
from .proof import ProofReader
from sbom_recovery.evidence.storage import save


class Response(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    task_id: str
    verdict: Literal["PENDING", "CONFIRMED", "INCORRECT", "UNKNOWN"] = "PENDING"
    notes: str = ""
    evidence_source_ids: list[str] = Field(default_factory=list)
    discovered_candidates: list[dict] = Field(default_factory=list)


class ReviewForm(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["gold-review-form-v1"] = "gold-review-form-v1"
    packet_sha256: str
    slot: Literal["A", "B"]
    reviewer_id: str = ""
    independent_human_review_attested: bool = False
    responses: list[Response]


def _task(kind, case, payload):
    return {"task_id":fingerprint([case.case_id,kind,payload]), "kind":kind, "case_id":case.case_id,
            "target":case.target, "environment":case.environment, "repository":case.repository,
            "commit":case.commit, "allowed_evidence":{k:v.model_dump(mode="json") for k,v in case.files.items()},
            **payload}


def export_reviews(run_path, out):
    run_path = Path(run_path).resolve(); out = Path(out)
    if out.exists(): raise FileExistsError(out)
    manifest = json.loads(run_path.read_text())
    tasks = []; discovery = []; contexts = {}; strata = {}
    for row in manifest["records"]:
        if row["status"] != "COMPLETE_MACHINE_QA":
            raise ValueError("Cannot silently exclude failed cases from annotation")
        case_path = Path(row["case_path"]); case = CaseManifest.model_validate_json(case_path.read_text())
        case.verify_files(case_path.parent)
        gold_path = Path(row["gold_path"]); ledger = LedgerV2.model_validate_json((gold_path/"canonical.json").read_text())
        reader = ProofReader(case_path); audit = reader.audit(ledger)
        if audit["status"] != "PASSED": raise ValueError("Unresolved provenance: " + case.case_id)
        queue = json.loads((gold_path/"annotation-queue.json").read_text())
        by_id = {c.claim_id:c for c in ledger.claims}
        ids = set(queue["random_audit_claim_ids"]) | set(queue["conflict_claim_ids"])
        if not ids <= by_id.keys(): raise ValueError("Annotation queue references unknown claims")
        contexts[case.case_id] = {"case_manifest_sha256":case.digest(), "evidence_root":str(case_path.parent),
                                  "gold_sha256":ledger.fingerprint()}
        strata.setdefault(case.ecosystem, []).append(case)
        for cid in sorted(ids):
            c = by_id[cid]
            proofs = [reader.inspect(c,e) for e in c.evidence]
            payload = {"claim_id":cid, "subject":c.subject, "instance_id":c.instance_id,
                       "field":c.predicate, "proposed_value":c.object, "layer":c.layer, "scope":c.scope,
                       "condition":c.condition, "proofs":proofs}
            tasks.append(_task("claim",case,payload))
        for index,issue in enumerate(queue["unresolved"]):
            tasks.append(_task("unresolved",case,{"issue_index":index,"issue":issue,
                "instruction":"Determine whether uncertainty is justified in this bounded source/profile; do not invent a value."}))
    rng = random.Random(42)
    for ecosystem,cases in sorted(strata.items()):
        case = rng.choice(sorted(cases,key=lambda c:c.case_id))
        task = _task("discovery",case,{"instruction":"Before claim review, independently inspect the bounded source/artifact evidence for missed components. Do not use scanner, resolver, prediction or gold inventories. Record candidate evidence; discovery is not automatically verified truth."})
        task["allowed_evidence"] = {k:v for k,v in task["allowed_evidence"].items() if v["kind"] in {"source","manifest","artifact"}}
        discovery.append(task)
    rng.shuffle(tasks)
    packet = {"schema_version":"gold-review-packet-v1", "run_manifest_sha256":fingerprint(manifest),
              "contexts":contexts, "tasks":tasks, "seed":42, "blinding":"No method names, predictions, scores or other reviewer's decisions",
              "identity_policy":"Human identity and independence are self-attested; not authenticated by this local tool"}
    packet["packet_sha256"] = fingerprint(packet)
    out.mkdir(parents=True)
    save(out/"packet.json",packet)
    discovery_packet = {"schema_version":"gold-review-packet-v1", "tasks":discovery, "seed":42,
                        "contexts":{t["case_id"]:{k:v for k,v in contexts[t["case_id"]].items() if k!="gold_sha256"} for t in discovery},
                        "blinding":"Discovery before claim review; no machine/scanner/resolver/gold inventories",
                        "run_manifest_sha256":fingerprint(manifest)}
    discovery_packet["packet_sha256"] = fingerprint(discovery_packet)
    save(out/"discovery-packet.json",discovery_packet)
    for slot in ("A","B"):
        form = ReviewForm(packet_sha256=packet["packet_sha256"],slot=slot,
                          responses=[Response(task_id=t["task_id"]) for t in tasks])
        save(out/("review-"+slot+".json"),form.model_dump(mode="json"))
        discovery_form = ReviewForm(packet_sha256=discovery_packet["packet_sha256"],slot=slot,
                                   responses=[Response(task_id=t["task_id"]) for t in discovery])
        save(out/("discovery-"+slot+".json"),discovery_form.model_dump(mode="json"))
    summary = {"status":"PENDING_INDEPENDENT_HUMAN_REVIEW", "tasks":len(tasks),
               "task_types":dict(Counter(t["kind"] for t in tasks)), "discovery_tasks":len(discovery), "packet_sha256":packet["packet_sha256"],
               "completed_reviews":0,"agreement":None,"labels_modified":False,"llm_api_calls":0}
    save(out/"summary.json",summary)
    (out/"README.md").write_text("# Independent gold review\n\n"
        "First give each reviewer discovery-packet.json and a separate discovery form. Collect those decisions BEFORE exposing packet.json or claim forms. "
        "Then give the claim packet and one blank review form to each independent human reviewer. Keep their decisions separate until submission. "
        "The packet binds proposed claims to real source selectors and hashes; source artifacts remain in the case store. "
        "No model-method identities or prediction scores are included. For discovery tasks, inspect the evidence directly and avoid opening gold inventories.\n\n"
        "Each reviewer fills reviewer_id and the human-independence attestation, then replaces PENDING with CONFIRMED, INCORRECT or UNKNOWN. "
        "Every completed response needs notes and at least one evidence_source_id from the task. Discovered candidates remain candidates. "
        "CONFIRMED on an unresolved task means the uncertainty is justified, not that an absent value was recovered.\n\n"
        "Run gold-review-check to validate submissions and count paired agreement. Empty forms do not count as completed reviews. "
        "This tool does not alter labels or automatically unlock benchmark scaling.\n")
    return summary


def check_reviews(packet_path, review_paths, out):
    out = Path(out)
    if out.exists(): raise FileExistsError(out)
    packet = json.loads(Path(packet_path).read_text()); claimed = packet.pop("packet_sha256")
    if fingerprint(packet) != claimed: raise ValueError("Review packet changed")
    tasks = {t["task_id"]:t for t in packet["tasks"]}
    if len(tasks) != len(packet["tasks"]): raise ValueError("Duplicate packet task")
    panels = {}; reviewers = {}; response_hashes = {}
    for path in review_paths:
        data = Path(path).read_text(); form = ReviewForm.model_validate_json(data)
        if form.packet_sha256 != claimed or form.slot in panels: raise ValueError("Packet mismatch or repeated reviewer slot")
        responses = {}; complete = {}
        for response in form.responses:
            if response.task_id not in tasks or response.task_id in responses: raise ValueError("Unknown or duplicate review task")
            responses[response.task_id] = response
            if response.verdict == "PENDING":
                if response.notes or response.evidence_source_ids or response.discovered_candidates:
                    raise ValueError("Pending response contains a decision payload")
                continue
            if not form.reviewer_id.strip() or not form.independent_human_review_attested:
                raise ValueError("Completed reviews require explicit independent-human attestation")
            if not response.notes.strip() or not response.evidence_source_ids:
                raise ValueError("Completed review requires notes and evidence")
            task = tasks[response.task_id]
            if not set(response.evidence_source_ids) <= task["allowed_evidence"].keys(): raise ValueError("Unknown evidence source")
            if response.discovered_candidates and task["kind"] != "discovery": raise ValueError("Candidates belong in discovery responses")
            complete[response.task_id] = response
        panels[form.slot] = complete
        if complete: reviewers[form.slot] = form.reviewer_id.strip()
        response_hashes[form.slot] = fingerprint(form.model_dump(mode="json"))
    if len(reviewers) == 2 and len({name.casefold() for name in reviewers.values()}) != 2:
        raise ValueError("The two panels need distinct reviewers")
    a,b = panels.get("A",{}),panels.get("B",{})
    paired = sorted(set(a)&set(b)); matches = sum(a[t].verdict == b[t].verdict for t in paired)
    disagreement = [t for t in paired if a[t].verdict != b[t].verdict]
    flagged = sorted({t for panel in panels.values() for t,r in panel.items()
                      if r.verdict in {"INCORRECT","UNKNOWN"} or r.discovered_candidates})
    result = {"status":"PENDING" if len(paired)<len(tasks) else "PAIRED_REVIEW_COMPLETE_REQUIRES_ADJUDICATION",
              "packet_sha256":claimed,"response_hashes":response_hashes,"tasks":len(tasks),
              "completed_by_slot":{slot:len(rows) for slot,rows in panels.items()},"paired":len(paired),
              "observed_agreement":matches/len(paired) if paired else None,
              "agreement_denominator":"Tasks with completed decisions from both distinct self-attested human reviewers",
              "disagreements":disagreement,"adjudication_queue":flagged,"labels_modified":False,
              "ready_for_scale":False,"next_gate":"Independent adjudication, discovery review and scanner-scope matching"}
    out.mkdir(parents=True); save(out/"review-status.json",result)
    return result
