"""Deterministic fixed-evidence pilot; predictions never open adjudicated labels."""
from collections import defaultdict
from pathlib import Path

from sbom_recovery.core.canonical import VerificationRecord
from .gold_contracts import ClaimV2, LedgerV2, fingerprint
from .gold_pipeline import Builder, validate_gold
from sbom_recovery.metrics.claim_scorer import ClaimScorer, claim_key
from sbom_recovery.core.formats import NativeDocument, package_purl
from sbom_recovery.evidence.storage import save
import json
import os
import subprocess
import uuid


def observations(case_path):
    builder = Builder(case_path,allowed_only=True)
    case = builder.case
    # Independent permitted-evidence extraction, with no adjudication file argument.
    # This information-rich diagnostic shares native declarations with machine gold.
    evidence = builder.build()
    converted = []
    for c in evidence.claims:
        if all(e.source_id in case.allowed_evidence for e in c.evidence):
            data=c.model_dump(mode="json")
            data.update(role="observation",status="unknown",verification=VerificationRecord().model_dump())
            converted.append(ClaimV2.model_validate(data))
    ledger=LedgerV2(case_id=case.case_id,case_manifest_sha256=case.digest(),role="observation",claims=converted)
    initial=LedgerV2(case_id=case.case_id,case_manifest_sha256=case.digest(),role="observation")
    # Scanner-only facts are retained without inventing runtime scope/instance correspondence.
    from sbom_recovery.core.canonical import EvidenceItem
    from .gold_contracts import contained
    for sid in case.allowed_evidence:
        item=case.files[sid]
        if item.kind!="scanner": continue
        native=NativeDocument(json.loads(contained(builder.root,item.path).read_text()))
        for ref,pkg in native.packages().items():
            identity=package_purl(pkg,native.format) or "urn:scanner:"+sid+":"+ref
            for field,rawkey in [("name","name"),("version","versionInfo" if native.format=="spdx" else "version")]:
                if not pkg.get(rawkey): continue
                c=ClaimV2(case_id=case.case_id,target_id=case.target,instance_id=sid+":"+ref,subject=identity,
                    predicate=field,object=pkg[rawkey],layer="G1_source",scope="unknown",role="observation",
                    evidence=[EvidenceItem(source_id=sid,source_type="scanner_sbom",artifact_sha256=item.sha256,
                                           locator=ref+":"+rawkey,raw_value=pkg[rawkey])])
                initial.add_claim(c); ledger.add_claim(c)
    return initial,ledger


def decide(ledger, strategy):
    groups=defaultdict(list)
    for c in ledger.claims:
        key=claim_key(c)
        if c.predicate=="depends_on": key+=(fingerprint(c.object),)
        groups[key].append(c)
    result=LedgerV2(case_id=ledger.case_id,case_manifest_sha256=ledger.case_manifest_sha256,role="prediction")
    for group in groups.values():
        values=defaultdict(list)
        for c in group: values[fingerprint(c.object)].append(c)
        chosen=None
        if strategy=="B0_priority": chosen=group[0]
        elif strategy=="B1_majority":
            votes={v:len({e.source_id for c in cs for e in c.evidence}) for v,cs in values.items()}
            best=max(votes.values())
            winners=[v for v,n in votes.items() if n==best]
            if len(winners)==1: chosen=values[winners[0]][0]
        else:
            expected={"G1_source":"manifest_source","G2_resolved":"native_resolver_report",
                      "G3_artifact":"installed_artifact_metadata"}[group[0].layer]
            authority={v for v,cs in values.items() if any(e.source_type==expected for c in cs for e in c.evidence)}
            if len(authority)==1: chosen=values[next(iter(authority))][0]
        data=(chosen or group[0]).model_dump(mode="json")
        data.update(role="prediction",status="verified" if chosen else "unknown",verification=VerificationRecord().model_dump())
        result.add_claim(ClaimV2.model_validate(data))
    return result


def run_e1(case_path,out,isolated=True,code_root=None):
    out=Path(out); out.mkdir(parents=True,exist_ok=False)
    initial,ledger=observations(case_path)
    ledger.save(out/"evidence-ledger.json"); initial.save(out/"scanner-observations.json")
    methods=("B0_priority","B1_majority","B2_field_aware")
    if isolated:
        image=subprocess.check_output(["docker","image","inspect","sbom-recovery-worker:v1","--format","{{.Id}}"],text=True).strip()
        code_root=Path(code_root or Path(__file__).resolve().parents[1]).resolve()
        container_name="gold-e1-"+uuid.uuid4().hex
        command=["docker","run","--rm","--name",container_name,"--network","none","--read-only","--user",f"{os.getuid()}:{os.getgid()}",
            "--cap-drop=ALL","--security-opt=no-new-privileges","--memory=512m","--cpus=1","--pids-limit=64",
            "--tmpfs","/tmp:rw,size=64m","-e","PYTHONPATH=/code",
            "-v",str(code_root/"sbom_recovery")+":/code/sbom_recovery:ro",
            "-v",str((out/"evidence-ledger.json").resolve())+":/input/ledger.json:ro",
            "--entrypoint","python",image,"-B","-c",
            "import json; from sbom_recovery.gold_contracts import LedgerV2; from sbom_recovery.gold_pilot import decide; "
            "l=LedgerV2.model_validate_json(open('/input/ledger.json').read()); "
            "print(json.dumps({s:decide(l,s).model_dump(mode='json') for s in ['B0_priority','B1_majority','B2_field_aware']}))"]
        try:
            response=subprocess.run(command,capture_output=True,text=True,timeout=120)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker","stop","-t","2",container_name],capture_output=True)
            save(out/"worker-boundary.json",{"command":command,"oracle_mounted":False,"network":"none",
                "image_id":image,"status":"TIMEOUT"})
            raise RuntimeError("Isolated deterministic worker timed out")
        save(out/"worker-boundary.json",{"command":command,"oracle_mounted":False,"network":"none","image_id":image,
            "returncode":response.returncode,"stderr":response.stderr})
        if response.returncode: raise RuntimeError("Isolated deterministic worker failed")
        predictions={m:LedgerV2.model_validate(v) for m,v in json.loads(response.stdout).items()}
    else:
        predictions={method:decide(ledger,method) for method in methods}
    for method,prediction in predictions.items(): prediction.save(out/(method+".json"))
    # Seal all predictions before evaluator constructs its independent reference.
    seal={k:v.fingerprint() for k,v in predictions.items()}
    save(out/"prediction-seal.json",seal)
    builder=Builder(case_path); gold=builder.build(); validate_gold(case_path,gold)
    scores=[ClaimScorer.evaluate_case(builder.case.case_id,method,gold,initial,pred,evidence_ledger=ledger).model_dump(mode="json")
            for method,pred in predictions.items()]
    result={"status":"ENGINEERING_DIAGNOSTIC","scores":scores,"evidence_sha256":ledger.fingerprint(),
        "prediction_seal":seal,"llm_api_calls":0,"calibration":"UNMEASURED","human_review":"PENDING",
        "limits":["Native evidence may already suffice for deterministic recovery",
                  "Unmapped scanner scopes/instances remain unjudged; component matching is not measured",
                  "No claim of agent superiority or multi-language generalization"]}
    save(out/"summary.json",result)
    return result
