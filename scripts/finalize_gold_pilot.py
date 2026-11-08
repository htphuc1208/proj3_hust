"""Seal new cases with scanner inputs, artifact bytes, machine QA and E1 diagnostics."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.parse import urlsplit

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.collect_gold_pilot import fetch,sha,now
from sbom_recovery.gold_contracts import CaseManifest,FrozenFile,contained
from sbom_recovery.gold_pipeline import build_gold
from sbom_recovery.gold_pilot import run_e1
from sbom_recovery.storage import save

ROOT=Path(__file__).resolve().parents[1]


def finalize(captures,out,report_dir,overrides=None):
    captures=Path(captures).resolve(); out=Path(out).resolve(); report_dir=Path(report_dir).resolve()
    out.mkdir(parents=True,exist_ok=False); report_dir.mkdir(parents=True,exist_ok=False)
    # Freeze all implementation bytes before inference/evaluation.
    bundle=report_dir/"source_bundle"; bundle.mkdir()
    shutil.copytree(ROOT/"sbom_recovery",bundle/"sbom_recovery",ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(ROOT/"scripts",bundle/"scripts",ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("research_core.py","resolver.py","registry_provider.py","benchmark.py","graph_triage.py","requirements-agent.txt"):
        shutil.copyfile(ROOT/name,bundle/name)
    shutil.copytree(ROOT/"research/schemas",bundle/"research/schemas")
    save(report_dir/"source-manifest.json",{str(p.relative_to(bundle)):sha(p) for p in bundle.rglob("*.py")})
    records=[]
    for previous in sorted((captures/"cases").glob("*/case.json")):
        case=CaseManifest.model_validate_json(previous.read_text()); case.verify_files(previous.parent)
        if overrides and (Path(overrides)/"cases"/case.case_id/"case.json").exists():
            replacement=Path(overrides)/"cases"/case.case_id/"case.json"
            updated=CaseManifest.model_validate_json(replacement.read_text())
            if updated.commit!=case.commit: raise ValueError("Build correction changed source commit")
            case=updated; previous=replacement.resolve(); case.verify_files(previous.parent)
        root=out/"cases"/case.case_id; root.mkdir(parents=True)
        row={"case_id":case.case_id,"ecosystem":case.ecosystem,"status":"PENDING"}; records.append(row)
        try:
            for item in case.files.values():
                dest=contained(root,item.path); dest.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(contained(previous.parent,item.path),dest)
            source=previous.parent/"source"/case.target
            for name in ["setup.py"]:
                candidate=source/name
                if candidate.is_file():
                    relative="source/"+("" if case.target=="." else case.target+"/")+name
                    dest=contained(root,relative); dest.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(candidate,dest)
                    case.files["manifest:"+name]=FrozenFile(path=relative,sha256=sha(dest),kind="manifest")
            # Freeze downloadable distributions selected by pip. Validate their install-report hashes.
            report=previous.parent/"native/install-report.json"
            if case.ecosystem=="pypi" and report.exists():
                shutil.copyfile(report,root/"native/install-report.json")
                for index,item in enumerate(json.loads(report.read_text()).get("install",[])):
                    download=item.get("download_info",{}); url=download.get("url","")
                    expected=download.get("archive_info",{}).get("hashes",{}).get("sha256")
                    parsed=urlsplit(url)
                    if parsed.scheme!="https" or not expected: continue
                    if parsed.hostname!="files.pythonhosted.org" or parsed.username or parsed.password:
                        raise ValueError("Unexpected distribution artifact host")
                    raw=fetch(url,limit=30_000_000)
                    if hashlib.sha256(raw).hexdigest()!=expected: raise ValueError("Distribution digest mismatch")
                    relative="artifacts/"+url.split("/")[-1]
                    dest=contained(root,relative); dest.parent.mkdir(exist_ok=True); dest.write_bytes(raw)
                    case.files["artifact:"+str(index)]=FrozenFile(path=relative,sha256=expected,kind="artifact")
            scans=root/"scanners"; scans.mkdir()
            for tool in ("syft","trivy"):
                binary=ROOT/"research/.work"/tool
                native=scans/(tool+".spdx.json")
                image=case.environment["image_id"] if case.ecosystem=="pypi" else "sbom-recovery-worker:v1"
                image_id=subprocess.check_output(["docker","image","inspect",image,"--format","{{.Id}}"],text=True).strip()
                args=["docker","run","--rm","--name","gold-scan-"+tool+"-"+case.case_id.lower(),
                    "--network","none","--read-only","--user",f"{os.getuid()}:{os.getgid()}","--cap-drop=ALL",
                    "--security-opt=no-new-privileges","--memory=1g","--cpus=1","--pids-limit=64",
                    "--tmpfs","/tmp:rw,size=256m","-v",str(source)+":/src:ro","-v",str(binary)+":/tool:ro",
                    "--entrypoint","/tool",image_id]
                if tool=="syft": args += ["scan","dir:/src","-o","spdx-json"]
                else: args += ["fs","--cache-dir","/tmp/trivy","--offline-scan","--skip-db-update","--skip-java-db-update","--format","spdx-json","/src"]
                started=time.monotonic()
                with native.open("w") as stdout,(scans/(tool+".log")).open("w") as stderr:
                    try:
                        result=subprocess.run(args,stdout=stdout,stderr=stderr,timeout=180)
                        code=result.returncode
                    except subprocess.TimeoutExpired:
                        subprocess.run(["docker","stop","-t","2",args[args.index("--name")+1]],capture_output=True)
                        code=-1
                save(scans/(tool+"-execution.json"),{"command":args,"returncode":code,"seconds":time.monotonic()-started,
                    "binary_sha256":sha(binary),"image_id":image_id,"network":"none"})
                if code==0:
                    json.loads(native.read_text())
                    case.files["scanner:"+tool]=FrozenFile(path=native.relative_to(root).as_posix(),sha256=sha(native),kind="scanner")
                row[tool+"_status"]="COMPLETE" if code==0 else "FAILED"
            case.allowed_evidence=[key for key,item in case.files.items() if item.kind!="annotation"]
            case.evidence_cutoff=now()
            save(root/"case.json",case.model_dump(mode="json"))
            row["gold"]=build_gold(root/"case.json",out/"gold"/case.case_id)
            result=run_e1(root/"case.json",out/"e1"/case.case_id,code_root=bundle)
            row.update(status="COMPLETE_MACHINE_QA",case_path=str(root/"case.json"),gold_path=str(out/"gold"/case.case_id),
                       e1_path=str(out/"e1"/case.case_id),resolution_status=case.resolution_status,
                       evidence_sha256=result["evidence_sha256"],commit=case.commit)
        except Exception as exc: row.update(status="FAILED",error=str(exc))
        save(report_dir/"manifest.json",{"status":"RUNNING","records":records})
        print(json.dumps(row),flush=True)
    result={"status":"MACHINE_QA_COMPLETE_HUMAN_REVIEW_PENDING" if len(records)==9 and all(r["status"]=="COMPLETE_MACHINE_QA" for r in records) else "PARTIAL",
        "records":records,"capture_root":str(captures),"artifact_root":str(out),"llm_api_calls":0,
        "human_review":"PENDING","agreement":"UNMEASURED","generalization":"UNMEASURED",
        "legacy_e1_e2_validity":"Historical diagnostics; mismatched scope/oracle access excludes superiority claims"}
    save(report_dir/"manifest.json",result)
    return result


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--captures",required=True);p.add_argument("--out",required=True);p.add_argument("--report-dir",required=True)
    p.add_argument("--overrides")
    a=p.parse_args();finalize(a.captures,a.out,a.report_dir,a.overrides)
