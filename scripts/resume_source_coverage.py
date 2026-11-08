#!/usr/bin/env python3
"""Resume interrupted source coverage without rerunning completed Ninka work.

Cached measurements are independently rechecked with the pinned field analyzer.
This script never reads installed-reference labels or modifies raw scanner SBOMs.
"""
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research_core import load, digest, now
from sbom_recovery.baselines import coverage, UNIFIER_COMMIT
from sbom_recovery.campaign import source_comparison_job
from sbom_recovery.storage import save


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--captures",required=True)
    p.add_argument("--previous",required=True)
    p.add_argument("--out",required=True)
    p.add_argument("--workers",type=int,default=2)
    args=p.parse_args()
    out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    rows=[];pending=[]
    for report in sorted(Path(args.captures).glob("*/capture.json")):
        capture=load(report)
        if capture["status"]!="COMPLETE": continue
        name=report.parent.name
        existing=Path(args.previous)/name/"comparison.json"
        if existing.exists():
            prior=load(existing)
            native=existing.parent/"unified.spdx.json"
            if prior["details"]["commit"]!=UNIFIER_COMMIT or prior["source_binding"]!=capture["source"]:
                raise ValueError("Cached source binding differs: "+name)
            recomputed=coverage(load(native))
            if recomputed!=prior["coverage"]["sbom-unifier"]:
                raise ValueError("Cached field measurement differs: "+name)
            destination=out/name
            destination.mkdir(exist_ok=True)
            for file in existing.parent.iterdir():
                if file.is_file() and not (destination/file.name).exists(): shutil.copyfile(file,destination/file.name)
            save(destination/"cache_reverification.json",{"verified_at":now(),"prior_result_sha256":digest(existing),
                "unified_sha256":digest(native),"field_counts_recomputed_equal":True,
                "original_input_digests_recorded":False,"runner_sha256":digest(__file__),
                "interpretation":"Rechecked field presence on the preserved tool output; no new correctness assertion"})
            rows.append({"project":name,**prior,"cache_reused":True})
        else:
            pending.append((str(report.parent),str(out/name)))
    print({"cached_reverified":len(rows),"pending":len(pending)},flush=True)
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures=[pool.submit(source_comparison_job,*job) for job in pending]
        for future in as_completed(futures):
            result=future.result();rows.append(result)
            save(out/"progress.json",{"completed":len(rows),"total":len(rows)+len(futures)-sum(f.done() for f in futures),"updated_at":now()})
            print({"project":result["project"],"status":result["status"],"completed":len(rows)},flush=True)
    save(out/"source_summary.json",{"records":rows,"source_scope_only":True,"runner_sha256":digest(__file__),
                                    "status":"COMPLETE_WITH_EXPLICIT_UNAVAILABLE_OR_FAILED_CASES"})


if __name__=="__main__": main()
