"""Offline audit of sealed development predictions, not a new benchmark run."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import shutil
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sbom_recovery.formats import validate_native
from sbom_recovery.gold_contracts import CaseManifest,contained
from sbom_recovery.materialized_scope import (
    digest,evaluate_scope,match_files,metadata_control,metadata_files,verify_integrity,
)
from sbom_recovery.storage import save

ROOT=Path(__file__).resolve().parents[1]


def read(path):return json.loads(Path(path).read_text())


def require(condition,message):
    if not condition:raise ValueError(message)


def check_case(row,worker):
    root=Path(row["case_root"]);context=read(root/"source-context.json")
    case_path=Path(context["parent_case"]);case=CaseManifest.model_validate_json(case_path.read_text())
    require(case.digest()==row["parent_case_sha256"]==context["parent_case_sha256"],"Parent case changed")
    case.verify_files(case_path.parent)
    catalog=read(root/"inspection/evidence/catalog.json")
    require(metadata_files(root/"target",row["ecosystem"])==catalog["entries"],"Target metadata inventory changed")
    inputs=root/"prediction-input";config=read(inputs/"config.json")
    require(digest(inputs/"catalog.json")==config["catalog_sha256"]==digest(root/"inspection/evidence/catalog.json"),"Public catalog changed")
    boundary=read(root/"worker-boundary.json");command=boundary["command"]
    require(boundary["oracle_mounted"] is False and boundary["network"]=="none","Invalid worker role declaration")
    require("--network" in command and command[command.index("--network")+1]=="none","Prediction used network")
    require(worker in command and "--read-only" in command and "--cap-drop=ALL" in command,"Worker isolation changed")
    mounts=[command[i+1].rsplit(":",2) for i,value in enumerate(command) if value=="-v"]
    expected={"/input":(inputs,"ro"),"/target":(root/"target","ro"),"/out":(root/"predictions","rw"),
              "/code/sbom_recovery":(root.parents[1]/"source_bundle/sbom_recovery","ro")}
    require(len(mounts)==len(expected),"Unexpected prediction mount count")
    for host,destination,mode in mounts:
        require(destination in expected,"Unexpected prediction destination")
        path,expected_mode=expected[destination]
        require(Path(host).resolve()==path.resolve() and mode==expected_mode,"Unexpected prediction mount/source")
    require(digest(inputs/"config.json")==boundary["input_config_sha256"],"Worker config changed")
    prediction_root=root/"predictions";seal=read(root/"prediction-seal.json")
    actual={p.relative_to(prediction_root).as_posix():digest(p) for p in prediction_root.rglob("*.json")}
    require(actual==seal,"Sealed prediction changed")
    evaluation=read(root/"evaluation.json");reference_path=root/"inspection/oracle/reference.json";reference=read(reference_path)
    require(digest(reference_path)==evaluation["reference_sha256"],"Reference changed")
    require(reference["native_sha256"]==digest(root/"oracle/native.json"),"Native snapshot changed")
    require(evaluation["predictions_sealed_before_evaluation"] is True,"Missing separation record")
    scores={s["scanner"]:s for s in evaluation["scores"]};arms=[]
    for scan in config["scanners"]:
        tool=scan["id"];source=inputs/scan["filename"]
        require(digest(source)==scan["sha256"],"Scanner input changed")
        require(digest(ROOT/"research/.work"/tool)==scan["binary_sha256"],"Scanner binary changed")
        document=read(source);bindings=read(prediction_root/tool/"bindings.json")
        require(bindings==match_files(document,catalog,root/"target"),"File evidence binding not reproducible")
        recovered,control=metadata_control(document,catalog,root/"target",bindings)
        require(recovered==read(prediction_root/tool/"recovered.spdx.json"),"Correction not reproducible")
        require(control==read(prediction_root/tool/"control.json"),"Control provenance changed")
        recomputed=evaluate_scope(document,recovered,bindings,reference)
        recomputed.update(scanner=tool,binding_counts=bindings["counts"],native_validity=validate_native(recovered),
            correction_records=len(control["proposals"]),control_unknowns=len(control["unresolved"]))
        require(recomputed==scores[tool],"Evaluator result not reproducible")
        require(validate_native(document)["valid"] and recomputed["native_validity"]["valid"],"Invalid native SPDX")
        group_sizes=Counter(len(r["coordinate_group_evidence_ids"]) for r in bindings["records"] if r["status"]=="LOCK_CORROBORATED_COORDINATE_GROUP")
        arms.append({"scanner":tool,"status":"CHECKED","packages":len(document.get("packages",[])),
            "binding_counts":bindings["counts"],"coordinate_group_sizes":dict(group_sizes),
            **{k:v for k,v in recomputed.items() if k not in {"records","scanner","binding_counts"}}})
    failures=row.get("scanner_failures",[])
    require({s["id"] for s in config["scanners"]}|{f["scanner"] for f in failures}=={"syft","trivy"},"Missing planned scanner arm")
    for failure in failures:
        require(failure["status"]=="FAILED" and Path(failure["log"]).is_file(),"Failure lacks retained log")
    for name in ("wheel-manifest.json","artifact-manifest.json"):
        if not (root/name).exists():continue
        record=read(root/name)
        if isinstance(record,dict):
            prefix="wheels" if name.startswith("wheel") else "artifacts"
            for filename,sha in record.items():require(digest(contained(root/prefix,filename))==sha,"Artifact store changed")
        else:
            for artifact in record:require(digest(contained(root/"target",artifact["path"]))==artifact["sha256"],"JAR store changed")
    if (root/"npm-spec.json").exists():
        verified=set()
        for record in read(root/"npm-spec.json")["instances"].values():
            if not record["path"] or record["artifact_path"] in verified:continue
            verify_integrity(contained(root,record["artifact_path"]).read_bytes(),record["integrity"])
            verified.add(record["artifact_path"])
    upgrades=root/"integrity-upgrades"
    for record_path in upgrades.glob("*.json"):
        if record_path.name.endswith(".metadata.json"):continue
        record=read(record_path);require(digest(contained(upgrades,record["metadata_file"]))==record["metadata_sha256"],"Registry supplement changed")
    if (root/"replay-parent.json").exists():
        replay=read(root/"replay-parent.json");origin=Path(replay["case_root"])
        require(digest(Path(replay["run_manifest"]))==replay["run_manifest_sha256"],"Replay parent manifest changed")
        require(digest(origin/"source-context.json")==replay["case_context_sha256"],"Replay context changed")
        require(digest(origin/"inspection/evidence/catalog.json")==replay["catalog_sha256"],"Replay catalog changed")
        require(digest(origin/"oracle/native.json")==replay["native_sha256"]==reference["native_sha256"],"Replayed native input changed")
        require(metadata_files(origin/"target",row["ecosystem"])==catalog["entries"],"Original and copied metadata differ")
    return {"case_id":row["case_id"],"status":"CHECKED_WITH_RETAINED_FAILURES" if failures else "CHECKED",
        "ecosystem":row["ecosystem"],"reference_records":len(reference["records"]),"reference_unknowns":len(reference["issues"]),
        "scanner_failures":failures,"arms":arms}


def verify(run_root,out):
    run_root=Path(run_root).resolve();out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
    manifest=read(run_root/"manifest.json");protocol=read(run_root/"protocol.json")
    validation_source=out/"validation_source";validation_source.mkdir()
    files=[Path(__file__),ROOT/"tests/test_materialized_scope.py"]
    for path in files:shutil.copyfile(path,validation_source/path.name)
    source_hashes={p.relative_to(validation_source).as_posix():digest(p) for p in validation_source.iterdir()}
    records=[];failures=[]
    for name,sha in protocol["source_bundle_hashes"].items():
        if digest(contained(run_root/"source_bundle",name))!=sha:failures.append({"source":name,"error":"Frozen source changed"})
    for name in ("sbom_recovery/materialized_scope.py","sbom_recovery/materialized_worker.py","scripts/run_materialized_scope.py"):
        if digest(ROOT/name)!=protocol["source_bundle_hashes"][name]:failures.append({"source":name,"error":"Live checker imports do not match frozen method"})
    tool_manifest=run_root/"tool-data/manifest.json"
    if tool_manifest.exists():
        for name,sha in read(tool_manifest)["files"].items():
            if digest(contained(run_root/"tool-data/trivy-cache",name))!=sha:failures.append({"tool_data":name,"error":"Frozen scanner data changed"})
    for row in manifest["records"]:
        if row["status"] not in {"COMPLETE","PARTIAL_SCANNERS"}:
            records.append({"case_id":row["case_id"],"status":"RETAINED_OPERATIONAL_FAILURE","error":row.get("error")});continue
        try:records.append(check_case(row,protocol["worker_image"]))
        except Exception as exc:failures.append({"case_id":row["case_id"],"error":str(exc)})
    all_arms=[arm for row in records for arm in row.get("arms",[])];tool_summary={}
    for tool in protocol["planned_scanners"]:
        arms=[a for a in all_arms if a["scanner"]==tool];counts=Counter()
        for arm in arms:counts.update(arm["binding_counts"])
        tool_summary[tool]={"checked_arms":len(arms),"packages":sum(a["packages"] for a in arms),"binding_counts":dict(counts),
            "correction_records":sum(a["correction_records"] for a in arms)}
        for metric in ["identity_before","identity_after","version_before","version_after"]:
            correct=sum(a[metric]["correct"] for a in arms);eligible=sum(a[metric]["eligible"] for a in arms)
            tool_summary[tool][metric]={"correct":correct,"eligible":eligible,"rate":correct/eligible if eligible else None}
    result={"status":"PASSED" if not failures else "FAILED","manifest_sha256":digest(run_root/"manifest.json"),
        "validation_source_hashes":source_hashes,"records":records,"failures":failures,"summary":tool_summary,
        "planned_cases":len(manifest["records"]),"checked_cases":sum(r["status"].startswith("CHECKED") for r in records),
        "checked_arms":len(all_arms),"llm_api_calls":0,"human_review":"PENDING",
        "scope":"Development target metadata only; conditional matching denominators do not establish full component accuracy",
        "unmeasured":["full inventory completeness","edges","vulnerability recovery","triage delta","false assurance reduction","calibration","agent advantage"]}
    save(out/"verification.json",result)
    print(json.dumps({"status":result["status"],"checked_cases":result["checked_cases"],"checked_arms":len(all_arms),"failures":failures,"summary":tool_summary}),flush=True)
    return result


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--run",required=True);parser.add_argument("--out",required=True)
    args=parser.parse_args();result=verify(args.run,args.out)
    if result["status"]!="PASSED":raise SystemExit(1)
