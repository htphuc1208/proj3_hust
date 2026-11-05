"""Local research UI API. Inputs are selected captures or uploaded JSON, never arbitrary paths."""
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import threading
import time
import uuid
import subprocess
import sys

from research_core import load
from sbom_recovery.budget_recover import recover
from sbom_recovery.formats import NativeDocument, package_purl, validate_native
from sbom_recovery.scope import installed_candidates
from sbom_recovery.freeze import freeze
from sbom_recovery.storage import save

ROOT=Path(__file__).resolve().parents[1]
CAPTURES=ROOT/"research/.work/m25-cohort-captures-v2"
RUNS=ROOT/"runs"
JOBS={}
LOCK=threading.Lock()
MODEL="Qwen/Qwen3.6-35B-A3B-FP8"
POLICIES={"single_agent_reconciliation","fixed_order","cheapest_source","unresolved_priority"}


def projects():
    rows=[]
    for root in sorted(CAPTURES.iterdir()) if CAPTURES.exists() else []:
        if not (root/"context.json").is_file() or not (root/"capture.json").is_file():continue
        info=load(root/"capture.json")
        rows.append({"name":root.name,"version":info["project"]["version"],
                     "scanners":[s for s in ("syft.spdx.json","trivy.spdx.json") if (root/"runtime"/s).is_file()]})
    return rows


def safe_root(name):
    if not isinstance(name,str) or not re.fullmatch(r"[A-Za-z0-9_.-]+",name):raise ValueError("Invalid run identifier")
    root=RUNS/name
    if root.is_symlink() or root.resolve().parent!=RUNS.resolve():raise ValueError("Run path denied")
    return root


def episode_root(name):
    root=safe_root(name)
    if (root/"episode.json").is_file() and (root/"execution/worker/result.json").is_file():return root
    if (root/"episode/episode.json").is_file() and not (root/"episode").is_symlink():return root/"episode"
    raise ValueError("Budgeted recovery run not found")


def list_runs():
    rows=[]
    for root in sorted(RUNS.iterdir(),key=lambda p:p.stat().st_mtime,reverse=True):
        if not root.is_dir():continue
        try:
            episode=episode_root(root.name);data=load(episode/"episode.json")
            rows.append({"id":root.name,"policy":data["policy"],"status":data["status"],
                         "budget":data["budget"],"llm_api_calls":data["llm_api_calls"]})
        except (ValueError,OSError,KeyError):continue
        if len(rows)==50:break
    return rows


def graph(document,limit=90,profile="distribution_candidates"):
    native=NativeDocument(document)
    all_packages=native.packages()
    packages=installed_candidates(document)[0] if profile=="distribution_candidates" else all_packages
    selected=dict(list(packages.items())[:limit])
    return {"total_nodes":len(packages),"overall_nodes":len(all_packages),"profile":profile,"displayed_nodes":len(selected),
            "nodes":[{"id":ref,"name":row.get("name",ref),"purl":package_purl(row,native.format)} for ref,row in selected.items()],
            "edges":[list(e) for e in sorted(native.edges()) if e[0] in selected and e[1] in selected]}


def details(name):
    root=episode_root(name)
    result=load(root/"execution/worker/result.json")
    episode=load(root/"episode.json")
    state=load(root/"execution/worker/state.json")
    observed=load(root/"observation.json")
    native_before,native_after=NativeDocument(observed),NativeDocument(result["document"])
    return {"id":name,"status":episode["status"],"policy":episode["policy"],"budget":episode["budget"],
            "target_purls":load(root/"context.json").get("root_purls",[]),
            "llm_api_calls":episode["llm_api_calls"],"attempts":state["attempts"],
            "acquired_sources":len(state["acquired_source_ids"]),"source_ids":state["acquired_source_ids"],
            "validation":result["validation"],"assessment_counts":result["assessment_counts"],
            "added_edges":sorted(map(list,native_after.edges()-native_before.edges())),
            "removed_edges":result["retracted_edges"],"added_nodes":len(native_after.packages().keys()-native_before.packages().keys()),
            "proposals":result["proposals"],"assessments":result["assessments"],"candidates":result["candidates"],
            "conflicts":result["conflicts"],"observed_graph":graph(observed),"candidate_graph":graph(result["document"]),
            "observed_graph_all":graph(observed,profile="all"),"candidate_graph_all":graph(result["document"],profile="all"),
            "document":result["document"],"risk":load(root/"risk.json") if (root/"risk.json").is_file() else None,
            "trace":load(root/"execution/worker/trace.json"),"confidence":None,
            "scope":"Đồ thị khai báo có evidence; chưa xác minh artifact triển khai hoặc khả năng khai thác."}


def evidence(name,source_id):
    if not re.fullmatch(r"[a-f0-9]{64}",source_id):raise ValueError("Invalid evidence ID")
    root=episode_root(name);seal=load(root/"execution/worker/seal.json")
    if source_id not in seal["acquired"]:raise ValueError("Source was not acquired")
    from hashlib import sha256
    path=root/"execution/worker/acquired"/source_id
    if path.is_symlink():raise ValueError("Evidence symlink denied")
    raw=path.read_bytes()
    if sha256(raw).hexdigest()!=seal["acquired"][source_id]:raise ValueError("Evidence changed")
    return {"source_id":source_id,"sha256":seal["acquired"][source_id],"content":raw[:16000].decode(errors="replace"),"truncated":len(raw)>16000}


def start(params):
    allowed={"project","scanner","policy","budget","document","streaming"}
    if not isinstance(params,dict) or set(params)-allowed:raise ValueError("Unsupported job fields")
    project=next((p for p in projects() if p["name"]==params.get("project")),None)
    if not project or params.get("scanner") not in project["scanners"]:raise ValueError("Select a captured target and scanner")
    policy=params.get("policy","single_agent_reconciliation");budget=params.get("budget")
    if policy not in POLICIES or (budget is not None and (type(budget) is not int or budget not in (4,16))):raise ValueError("Unsupported policy or budget")
    if "streaming" in params and type(params["streaming"]) is not bool:raise ValueError("Invalid transport setting")
    if "document" in params:
        if not isinstance(params["document"],dict):raise ValueError("Expected an SBOM object")
        NativeDocument(params["document"])
        if not validate_native(params["document"])["valid"]:raise ValueError("Uploaded SBOM failed native validation")
    job_id=uuid.uuid4().hex
    name="ui-agent-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")+"-"+job_id[:8]
    with LOCK:JOBS[job_id]={"status":"QUEUED","run_id":name,"started":time.time(),"error":None}
    threading.Thread(target=execute,args=(job_id,params),daemon=True).start()
    return {"job_id":job_id,"run_id":name}


def execute(job_id,params):
    with LOCK:JOBS[job_id]["status"]="RUNNING";name=JOBS[job_id]["run_id"]
    try:
        capture=CAPTURES/params["project"];info=load(capture/"capture.json");context=load(capture/"context.json")
        context.update(evidence_cutoff=info["completed_at"],root_purls=[f"pkg:pypi/{info['project']['name']}@{info['project']['version']}"])
        inputs=RUNS/("ui-input-"+job_id);inputs.mkdir()
        save(inputs/"context.json",context)
        save(inputs/"observation.json",params.get("document",load(capture/"runtime"/params["scanner"])))
        snapshot=RUNS/"m25-osv-snapshot-v1/snapshot.json"
        code=inputs/'source_bundle';freeze(code)
        save(inputs/'job.json',{'input':str(inputs/'observation.json'),'context':str(inputs/'context.json'),
             'target':str(capture/'runtime/target'),'available_at':info['completed_at'],'out':str(RUNS/name),
             'policy':params.get('policy','single_agent_reconciliation'),'budget':params.get('budget'),
             'streaming':params.get('streaming',True),'advisory_snapshot':str(snapshot) if snapshot.exists() else None,
             'code':str(code),'image':load(ROOT/'research/.work/agent-worker-image/image.json')['image']})
        env=os.environ.copy();env['PYTHONPATH']=str(code)
        # A new interpreter uses the recorded controller bytes, unaffected by later UI edits.
        completed=subprocess.run([str(ROOT/'.venv/bin/python'),'-B','-m','sbom_recovery.budget_job','--config',str(inputs/'job.json')],
            cwd=code,env=env,capture_output=True,text=True,start_new_session=True)
        if completed.returncode:raise RuntimeError('Recovery controller failed')
        result=load(RUNS/name/'result.json')
        with LOCK:
            JOBS[job_id]['status']='COMPLETE' if result['status']=='COMPLETE' and result['native_valid'] else 'ERROR'
            if JOBS[job_id]['status']=='ERROR':JOBS[job_id]['error']=result['status'] if result['native_valid'] else 'NATIVE_VALIDATION_FAILED'
    except Exception as exc:
        with LOCK:JOBS[job_id].update(status="ERROR",error=type(exc).__name__)


def job_status(job_id):
    with LOCK:job=dict(JOBS[job_id])
    progress=RUNS/job["run_id"]/"progress.json"
    if progress.exists():job["progress"]=load(progress)
    job["elapsed_seconds"]=round(time.time()-job["started"],1)
    return job
