#!/usr/bin/env python3
"""Freeze fixed-ranked build-failure replacements without reading method scores."""
import argparse
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from research_core import load,digest,now
from sbom_recovery.fresh_selection import replace_failed
from sbom_recovery.storage import save


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort',required=True);parser.add_argument('--captures',required=True)
    parser.add_argument('--out',required=True)
    args=parser.parse_args();parent=load(args.cohort);captures=Path(args.captures)
    outcomes={}
    for row in parent['projects']:
        path=captures/row['name']/'capture.json'
        if not path.exists():raise ValueError('Unreported capture: '+row['name'])
        report=load(path)
        if report['project']['version']!=row['version']:raise ValueError('Capture version mismatch')
        outcomes[row['name']]={'status':report['status'],'evidence_sha256':digest(path)}
    revised=replace_failed(parent,outcomes)
    revised.update(parent_cohort_sha256=digest(args.cohort),created_at=now(),
                   replacement_source_sha256=digest(ROOT/'sbom_recovery/fresh_selection.py'))
    out=Path(args.out);out.mkdir(parents=True,exist_ok=False)
    save(out/'cohort.json',revised);save(out/'eligibility-inputs.json',outcomes)
    shutil.copyfile(__file__,out/'executed-runner.py')
    shutil.copyfile(ROOT/'sbom_recovery/fresh_selection.py',out/'executed-selection.py')
    print(revised['status'],'new replacements',len(revised['replacement_history'])-len(parent.get('replacement_history',[])))


if __name__=='__main__':main()
