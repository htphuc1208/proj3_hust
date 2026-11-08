#!/usr/bin/env python3
"""Freeze provisional chronological assignments; no labels or scores are read."""
import argparse
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from research_core import load,digest,now
from sbom_recovery.fresh_selection import assign
from sbom_recovery.storage import save


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--protocol',default='configs/unrestricted-study-v2.json')
    parser.add_argument('--out',required=True)
    args=parser.parse_args();config=load(args.protocol)
    pool=ROOT/config['candidate_pool'];identity=ROOT/config['repository_identity_audit']/'identities.json'
    identity_plan=load(identity.parent/'plan.json')
    if identity_plan['pool_sha256']!=digest(pool/'pool.json') or identity_plan['exclusions_sha256']!=digest(pool/'exclusions.json'):
        raise ValueError('Identity audit belongs to another frozen pool')
    out=Path(args.out);out.mkdir(parents=True,exist_ok=False)
    result=assign(load(pool/'pool.json'),load(identity),load(pool/'exclusions.json'),
                  load(ROOT/config['development_screened_roots']),config)
    result.update(created_at=now(),protocol=config,protocol_sha256=digest(args.protocol),
                  pool_sha256=digest(pool/'pool.json'),identity_sha256=digest(identity),
                  selection_source_sha256=digest(ROOT/'sbom_recovery/fresh_selection.py'),
                  config={**load(ROOT/'configs/agent-recovery-v1.json'),
                     'partitions':{k:{**config['release_windows'][k],'count':n} for k,n in config['target_projects'].items()},
                     'target':config['target_environment'],
                     'unrestricted_capture_time':True,'freeze_wheels_before_install':True},model_calls=0)
    for row in result['projects']:
        row['registry_file']=str((pool/row['registry_file']).resolve())
    for rows in result['reserves'].values():
        for row in rows:row['registry_file']=str((pool/row['registry_file']).resolve())
    save(out/'cohort.json',result)
    shutil.copyfile(__file__,out/'executed-runner.py')
    shutil.copyfile(ROOT/'sbom_recovery/fresh_selection.py',out/'executed-selection.py')
    shutil.copyfile(args.protocol,out/'protocol.json')
    print(result['status'],result['counts'])


if __name__=='__main__':main()
