#!/usr/bin/env python3
"""Development-only budget matrix. All predictions precede independent scoring."""
from collections import Counter
from datetime import datetime, timezone
import argparse
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from research_core import load,digest
from sbom_recovery.budget_recover import recover
from sbom_recovery.budget_sources import prepare_catalog
from sbom_recovery.contracts import TargetContext
from sbom_recovery.formats import sha
from sbom_recovery.freeze import freeze
from sbom_recovery.storage import save


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True)
    parser.add_argument('--with-agent',action='store_true')
    args=parser.parse_args()
    from dotenv import load_dotenv
    load_dotenv(ROOT/'.env',override=False)
    out=Path(args.out).resolve();out.mkdir(parents=True,exist_ok=False)
    freeze(out/'source_bundle');shutil.copyfile(__file__,out/'executed-runner.py')
    cohort=load(ROOT/'runs/m25-cohort-buildable-v4/cohort.json')
    projects=[p for p in cohort['projects'] if p['partition']=='development']
    if len(projects)!=20:raise ValueError('Expected original 20 development projects')
    methods=['fixed_order','cheapest_source','unresolved_priority']+(['single_agent_reconciliation'] if args.with_agent else [])
    plan={'status':'DEVELOPMENT_DIAGNOSTIC','projects':[],'methods':methods,'budgets':[4,16],
          'cohort_sha256':digest(ROOT/'runs/m25-cohort-buildable-v4/cohort.json'),
          'source_manifest_sha256':digest(out/'source_bundle/source_manifest.json'),
          'runner_sha256':digest(__file__),'model':'Qwen/Qwen3.6-35B-A3B-FP8',
          'comparison':'same source catalog, same acquired-evidence gate v2, source contents provided via charged RPC only',
          'minimum_sources_for_fresh_study':32,'existing_development_does_not_establish_fresh_cohort_feasibility':True}
    for project in projects:
        capture=ROOT/'research/.work/m25-cohort-captures-v2'/project['name']
        info=load(capture/'capture.json');context=load(capture/'context.json')
        context.update(evidence_cutoff=info['completed_at'],root_purls=[f"pkg:pypi/{project['name']}@{project['version']}"])
        ctx=TargetContext.model_validate(context)
        catalog=prepare_catalog(capture/'runtime/target',ctx,info['completed_at'])
        save(out/'contexts'/f"{project['name']}.json",context)
        plan['projects'].append({'name':project['name'],'capture':str(capture),'available_at':info['completed_at'],
                                 'catalog_sha256':catalog['sha256'],'sources':len(catalog['sources']),
                                 'eligible_source_count_for_new_study':len(catalog['sources'])>=32})
    save(out/'plan.json',plan)
    records=[]
    for project in plan['projects']:
        capture=Path(project['capture'])
        for budget in plan['budgets']:
            for method in methods:
                destination=out/project['name']/f'budget-{budget}'/method
                try:
                    summary=recover(capture/'runtime/syft.spdx.json',out/'contexts'/f"{project['name']}.json",
                        capture/'runtime/target',project['available_at'],destination,policy=method,budget=budget,
                        streaming=True,code=out/'source_bundle')
                    record={'project':project['name'],'budget':budget,'method':method,'output':str(destination),**summary}
                except Exception as exc:
                    record={'project':project['name'],'budget':budget,'method':method,'status':'EXECUTION_ERROR',
                            'error_type':type(exc).__name__,'output':str(destination)}
                records.append(record)
                save(out/'progress.json',{'finished_arms':len(records),'total_arms':len(projects)*len(methods)*2,
                                         'status_counts':dict(Counter(r['status'] for r in records))})
                print(project['name'],budget,method,record['status'],flush=True)
    # Freeze the complete prediction matrix before opening reference labels.
    save(out/'prediction-matrix.json',{'plan_sha256':sha(plan),'sealed_at':datetime.now(timezone.utc).isoformat(),
         'predictions':{str(p.relative_to(out)):digest(p) for p in out.glob('*/budget-*/*/execution/worker/seal.json')}})
    from sbom_recovery.campaign import score_after_seal
    for record in records:
        destination=Path(record['output']);prediction=destination/'execution/worker/result.json'
        if not prediction.exists():continue
        result=load(prediction);seal=load(destination/'execution/worker/seal.json')
        observation=load(destination/'observation.json')
        if (sha(result)!=seal['result_sha256'] or sha(observation)!=seal['input_sha256']
                or sha(result['document'])!=seal['prediction_sha256']):raise ValueError('Prediction seal changed')
        if load(destination/'catalog.json')['sha256']!=next(p['catalog_sha256'] for p in plan['projects'] if p['name']==record['project']):
            raise ValueError('Unpaired source catalog')
        evaluation=score_after_seal(ROOT/'research/.work/m25-cohort-captures-v2'/record['project'],observation,result['document'])
        save(destination/'evaluation.json',evaluation)
        record.update(whole_edges=evaluation['whole_edges'],new_edges=evaluation['new_edges'],
                      unknown_labels=evaluation['unknown_label_edge_count'],assessment_counts=result['assessment_counts'])
    save(out/'summary.json',{'status':'COMPLETE_DEVELOPMENT_MATRIX' if all(r['status']=='COMPLETE' for r in records) else 'PARTIAL',
         'records':records,'projects':20,'methods':methods,'budgets':[4,16],
         'status_counts':dict(Counter(r['status'] for r in records)),
         'llm_api_calls':sum(r.get('llm_api_calls',0) for r in records),
         'source_count_eligible_projects':sum(p['eligible_source_count_for_new_study'] for p in plan['projects']),
         'new_heldout_roots':0,'agent_superiority':'UNESTABLISHED','security_utility':'UNMEASURED'})
    save(out/'artifact-hashes.json',{str(p.relative_to(out)):digest(p) for p in out.rglob('*') if p.is_file()})


if __name__=='__main__':main()
