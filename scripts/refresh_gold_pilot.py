"""Regenerate addressed proofs from frozen v2 case bytes into a fresh run.

This is development engineering validation, with no new source/registry collection
and no LLM inference. Original labels, predictions and source bundles stay intact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sbom_recovery.gold_contracts import LedgerV2, fingerprint
from sbom_recovery.gold_pipeline import build_gold
from sbom_recovery.gold_pilot import run_e1
from sbom_recovery.gold_review import export_reviews, check_reviews
from sbom_recovery.storage import save

ROOT = Path(__file__).resolve().parents[1]


def refresh(parent_path, out):
    parent_path = Path(parent_path).resolve(); out = Path(out).resolve()
    out.mkdir(parents=True,exist_ok=False)
    parent = json.loads(parent_path.read_text())
    bundle = out/"source_bundle"; bundle.mkdir()
    for name in ("sbom_recovery", "scripts", "tests"):
        shutil.copytree(ROOT/name,bundle/name,ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("research_core.py","resolver.py","registry_provider.py","benchmark.py","graph_triage.py","requirements-agent.txt"):
        shutil.copyfile(ROOT/name,bundle/name)
    shutil.copytree(ROOT/"research/schemas",bundle/"research/schemas")
    save(out/"source-manifest.json",{str(p.relative_to(bundle)):hashlib.sha256(p.read_bytes()).hexdigest() for p in bundle.rglob("*") if p.is_file()})
    records = []
    for previous in parent["records"]:
        row = {"case_id":previous["case_id"],"case_path":previous["case_path"],"status":"RUNNING",
               "gold_path":str(out/"gold"/previous["case_id"]),"e1_path":str(out/"e1"/previous["case_id"])}
        records.append(row)
        try:
            if previous["status"] != "COMPLETE_MACHINE_QA": raise ValueError("Parent case not complete")
            validation = build_gold(row["case_path"],row["gold_path"])
            old = LedgerV2.model_validate_json((Path(previous["gold_path"])/"canonical.json").read_text())
            new = LedgerV2.model_validate_json((Path(row["gold_path"])/"canonical.json").read_text())
            def values(ledger):
                return {c.claim_id:fingerprint({k:v for k,v in c.model_dump(mode="json").items() if k not in {"evidence","verification"}}) for c in ledger.claims}
            if values(old) != values(new): raise ValueError("Unexpected semantic label change; independent adjudication required")
            result = run_e1(row["case_path"],row["e1_path"],code_root=bundle)
            row.update(status="COMPLETE_MACHINE_QA",gold=validation,evidence_sha256=result["evidence_sha256"],
                       label_values_unchanged=True,legacy_gold_sha256=old.fingerprint(),gold_sha256=new.fingerprint())
        except Exception as exc: row.update(status="FAILED",error=str(exc))
        save(out/"manifest.json",{"status":"RUNNING","parent_manifest_sha256":fingerprint(parent),"records":records})
        print(json.dumps({"case_id":row["case_id"],"status":row["status"],"error":row.get("error")}),flush=True)
    result = {"status":"MACHINE_PROVENANCE_CHECKED_HUMAN_REVIEW_PENDING" if records and all(r["status"]=="COMPLETE_MACHINE_QA" for r in records) else "PARTIAL",
              "parent_manifest_sha256":fingerprint(parent),"records":records,"llm_api_calls":0,"source_or_registry_fetches":0,
              "human_review":"PENDING","scope_matching":"NOT_MEASURED","cases_replaced":False}
    save(out/"manifest.json",result)
    if result["status"] != "PARTIAL":
        result["review_packet"] = export_reviews(out/"manifest.json",out/"reviews")
        check_reviews(out/"reviews/packet.json",[out/"reviews/review-A.json",out/"reviews/review-B.json"],out/"review-status")
        check_reviews(out/"reviews/discovery-packet.json",[out/"reviews/discovery-A.json",out/"reviews/discovery-B.json"],out/"discovery-status")
        # The run manifest stays sealed: review-packet hashes bind exactly that manifest.
        save(out/"review-export.json",result["review_packet"])
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser();parser.add_argument("--parent",required=True);parser.add_argument("--out",required=True)
    args=parser.parse_args();refresh(args.parent,args.out)
