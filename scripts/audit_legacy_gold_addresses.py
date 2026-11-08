"""Reproduce targeted v2 citation-address findings, without changing old labels."""
from __future__ import annotations
import argparse
from collections import Counter
import email
import hashlib
import json
from pathlib import Path
import sys
import tomllib
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sbom_recovery.gold_contracts import CaseManifest,LedgerV2,contained
from sbom_recovery.storage import save


def audit(manifest_path,out):
    out=Path(out)
    if out.exists(): raise FileExistsError(out)
    manifest=json.loads(Path(manifest_path).read_text());records=[];totals=Counter()
    for row in manifest["records"]:
        case_path=Path(row["case_path"]);case=CaseManifest.model_validate_json(case_path.read_text())
        ledger=LedgerV2.model_validate_json((Path(row["gold_path"])/"canonical.json").read_text())
        if ledger.case_manifest_sha256!=case.digest(): raise ValueError("Legacy gold binding changed")
        sources={e.source_id for c in ledger.claims for e in c.evidence}
        case.verify_files(case_path.parent,sources)
        loaded={};findings=[]
        for claim in ledger.claims:
            for evidence in claim.evidence:
                if evidence.locator.startswith("proof-v1:"): continue
                path=contained(case_path.parent,case.files[evidence.source_id].path)
                if evidence.artifact_sha256!=case.files[evidence.source_id].sha256: raise ValueError("Citation hash changed")
                reason=None
                if claim.layer=="G2_resolved" and claim.predicate=="purl":
                    body=loaded.setdefault(evidence.source_id,None)
                    if body is None:body=loaded[evidence.source_id]=json.loads(path.read_text())
                    instance=evidence.locator[len("nodes/"):-len("/purl")]
                    node=next(n for n in body["nodes"] if n["id"]==instance)
                    if "purl" not in node:reason="DERIVED_PURL_WITHOUT_EXPLICIT_OPERATION"
                elif claim.layer=="G3_artifact" and claim.predicate=="checksum":
                    member=evidence.locator.rsplit(":",1)[0]
                    with zipfile.ZipFile(path) as archive:meta=email.message_from_bytes(archive.read(member))
                    if meta.get("checksum") is None:reason="WHOLE_ARTIFACT_HASH_CITED_AS_METADATA_FIELD"
                elif evidence.locator.startswith("source_model/"):
                    if "source_model" not in json.loads(path.read_text()):reason="SOURCE_MODEL_IN_DIFFERENT_BOUND_FILE"
                elif evidence.locator.startswith("project."):
                    if not tomllib.loads(path.read_text()).get("project"):reason="POETRY_TABLE_DIFFERENT_FROM_SELECTOR"
                if reason:
                    totals[reason]+=1
                    findings.append({"claim_id":claim.claim_id,"source_id":evidence.source_id,"source_sha256":evidence.artifact_sha256,
                                     "locator":evidence.locator,"finding":reason})
        records.append({"case_id":case.case_id,"findings":findings})
    result={"status":"TARGETED_SOURCE_ADDRESS_AUDIT","counts":dict(totals),"citations_flagged":sum(totals.values()),
        "records":records,"labels_modified":False,"claim_value_correctness":"NOT_ADJUDICATED",
        "limitations":"Four declared legacy patterns only, not a complete provenance audit or graph FP/FN evaluation",
        "audit_source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    out.mkdir(parents=True);save(out/"audit.json",result);return result


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--run",required=True);parser.add_argument("--out",required=True)
    args=parser.parse_args();result=audit(args.run,args.out)
    print(json.dumps({k:v for k,v in result.items() if k!="records"}))
