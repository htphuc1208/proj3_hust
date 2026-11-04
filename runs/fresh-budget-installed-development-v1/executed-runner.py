#!/usr/bin/env python3
"""Freeze a disjoint candidate pool and measure resolution feasibility before prediction.

This does not select a final cohort or claim installed-source eligibility. Fork
families, actual source counts, independent builds and security strata remain gates.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import httpx
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from container_runner import run_container
from research_core import load, digest, now
from sbom_recovery.cohort import github_repo, select_release
from sbom_recovery.storage import save


def pool(out, workers):
    out.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(__file__, out / 'executed-runner.py')
    design = load(ROOT / 'configs/evidence-acquisition-v1.json')
    old = load(ROOT / design['exclude_cohort'])
    excluded_names = {canonicalize_name(p['name']) for p in old['projects']}
    excluded_repos = {p['repository'].lower() for p in old['projects']}
    save(out / 'exclusions.json', {'cohort': design['exclude_cohort'],
         'cohort_sha256': digest(ROOT / design['exclude_cohort']),
         'names': sorted(excluded_names), 'repositories': sorted(excluded_repos),
         'fork_alias_audit': 'PENDING; no final cohort or predictions admitted'})
    commit = subprocess.check_output(['git', 'ls-remote', 'https://github.com/vinta/awesome-python.git', 'HEAD'],
                                     text=True, timeout=45).split()[0]
    if not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('Invalid source commit')
    url = f'https://raw.githubusercontent.com/vinta/awesome-python/{commit}/README.md'
    client = httpx.Client(timeout=30, follow_redirects=False)
    response = client.get(url); response.raise_for_status()
    (out / 'candidate-universe.md').write_bytes(response.content)
    repos = {github_repo(u) for u in re.findall(r'https://github\.com/[\w.-]+/[\w.-]+', response.text)}
    names = sorted({canonicalize_name(r.split('/')[-1]) for r in repos if r},
                   key=lambda n: hashlib.sha256(f"{design['selection_seed']}:{n}".encode()).hexdigest())
    (out / 'registry').mkdir()
    windows = {k: {'start': v.get('start'), 'end': v['end']} for k, v in design['release_windows'].items()}
    # Root size and target interpreter reuse the original, explicit build limits.
    build = load(ROOT / 'configs/agent-recovery-v1.json')
    save(out / 'plan.json', {'status': 'CANDIDATE_FEASIBILITY_ONLY', 'created_at': now(),
         'candidate_order': names, 'source_repository_commit': commit, 'source_url': url,
         'universe_sha256': digest(out / 'candidate-universe.md'), 'design_sha256': digest(ROOT / 'configs/evidence-acquisition-v1.json'),
         'source_sha256': digest(__file__), 'windows': windows, 'target': build['target'],
         'max_root_wheel_bytes': build['max_root_wheel_bytes'], 'max_capture_bytes': build['max_capture_bytes'],
         'minimum_installed_sources': design['minimum_permitted_target_metadata_sources'],
         'selection_metrics_used': [], 'model_calls': 0})

    def fetch(name):
        if name in excluded_names:
            return {'candidate': name, 'status': 'EXCLUDED_ORIGINAL_PACKAGE'}
        try:
            result = client.get(f'https://pypi.org/pypi/{name}/json')
            if result.status_code != 200:
                return {'candidate': name, 'status': f'HTTP_{result.status_code}'}
            payload = result.json(); info = payload['info']
            real_name = canonicalize_name(info['name'])
            links = [*(info.get('project_urls') or {}).values(), info.get('home_page')]
            linked = {github_repo(u) for u in links if isinstance(u, str) and github_repo(u)}
            verified = sorted(linked & repos)
            raw = out / 'registry' / (name + '.json'); raw.write_bytes(result.content)
            base = {'candidate': name, 'name': real_name, 'registry_sha256': digest(raw),
                    'registry_file': str(raw.relative_to(out)), 'queried_at': now(), 'linked_repositories': sorted(linked)}
            if real_name in excluded_names or linked & excluded_repos:
                return {**base, 'status': 'EXCLUDED_ORIGINAL_REPOSITORY_OR_ALIAS'}
            if not verified:
                return {**base, 'status': 'NO_UNIVERSE_REPOSITORY_LINK'}
            eligible = {part: select_release(payload, interval, build['max_root_wheel_bytes'])
                        for part, interval in windows.items()}
            return {**base, 'repository': verified[0], 'repository_url': 'https://github.com/' + verified[0],
                    'eligible': eligible, 'family_verification': 'PENDING',
                    'status': 'RELEASE_ELIGIBLE' if any(eligible.values()) else 'NO_ELIGIBLE_RELEASE'}
        except Exception as exc:
            return {'candidate': name, 'status': 'FETCH_FAILED', 'error_type': type(exc).__name__}
    records = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for index, row in enumerate(executor.map(fetch, names), 1):
            records.append(row)
            if index % 50 == 0:
                save(out / 'progress.json', {'finished': index, 'total': len(names), 'model_calls': 0})
                print(f'registry {index}/{len(names)}', flush=True)
    client.close()
    result = {'status': 'POOL_FROZEN_FINAL_COHORT_NOT_SELECTED', 'records': records,
              'status_counts': dict(Counter(r['status'] for r in records)), 'created_at': now(),
              'eligible_release_counts': {k: sum(bool(r.get('eligible', {}).get(k)) for r in records) for k in windows},
              'minimum_source_count_measured': False, 'family_audit_complete': False,
              'model_calls': 0, 'final_cohort': False}
    save(out / 'pool.json', result)
    print(result['status_counts'], flush=True)


def resolve(pool_root, out, partition, limit, workers):
    out.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(__file__, out / 'executed-runner.py')
    plan = load(pool_root / 'plan.json'); candidates = load(pool_root / 'pool.json')['records']
    rows = []; seen = set()
    for row in candidates:
        if row.get('eligible', {}).get(partition) and row['repository'] not in seen:
            rows.append(row); seen.add(row['repository'])
    rows = rows[:limit]
    image = load(ROOT / 'research/toolchain.json')['image']
    uv = Path(shutil.which('uv')).resolve()
    cache = (ROOT / 'research/.work/fresh-budget-uv-cache').resolve(); cache.mkdir(parents=True, exist_ok=True)
    frozen = {'status': 'RESOLUTION_FEASIBILITY_ONLY', 'pool_sha256': digest(pool_root / 'pool.json'),
              'partition': partition, 'names': [r['name'] for r in rows], 'image': image,
              'uv_sha256': digest(uv), 'source_sha256': digest(__file__),
              'horizon': plan['windows'][partition]['end'], 'model_calls': 0,
              'lock_pin_count_is_not_installed_source_count': True}
    save(out / 'plan.json', frozen)
    records = []
    def check(row):
        release = row['eligible'][partition]
        folder = out / row['name']; folder.mkdir()
        (folder / 'input').mkdir(); (folder / 'output').mkdir()
        (folder / 'input/root.in').write_text(f"{row['name']}=={release['version']}\n")
        args = ['docker', 'run', '--rm', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--memory=2g', '--cpus=1', '--pids-limit=128', '--user', f'{os.getuid()}:{os.getgid()}',
                '-e', 'UV_CACHE_DIR=/cache/uv', '-v', f'{uv}:/tools/uv:ro', '-v', f'{cache}:/cache:rw',
                '-v', f'{folder / "input"}:/input:ro', '-v', f'{folder / "output"}:/out:rw',
                '--entrypoint', '/tools/uv', image, 'pip', 'compile', '/input/root.in',
                '--python', '/usr/local/bin/python', '--exclude-newer', frozen['horizon'], '--generate-hashes',
                '--only-binary', ':all:', '--default-index', 'https://pypi.org/simple', '-o', '/out/requirements.lock']
        started = now()
        try:
            result = run_container(args, timeout=240)
            (folder / 'resolve.log').write_text(result.stdout + result.stderr)
            lock = folder / 'output/requirements.lock'
            pins = re.findall(r'^([A-Za-z0-9_.-]+)==([^\s;\\]+)', lock.read_text(), re.M) if lock.is_file() else []
            record = {'name': row['name'], 'repository': row['repository'], 'partition': partition,
                      'version': release['version'], 'status': 'RESOLVED' if result.returncode == 0 and pins else 'RESOLUTION_FAILED',
                      'exit_code': result.returncode, 'locked_name_pins': len(pins),
                      'lock_sha256': digest(lock) if lock.is_file() else None}
        except Exception as exc:
            record = {'name': row['name'], 'partition': partition, 'status': 'EXECUTION_FAILED', 'error_type': type(exc).__name__}
        record.update(started_at=started, completed_at=now(), command=args, predictions_run=False)
        save(folder / 'result.json', record)
        return record
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for row in executor.map(check, rows):
            records.append(row)
            save(out / 'progress.json', {'finished': len(records), 'total': len(rows),
                                       'status_counts': dict(Counter(r['status'] for r in records))})
            print(row['name'], row['status'], row.get('locked_name_pins'), flush=True)
    save(out / 'summary.json', {'status': 'FEASIBILITY_MEASURED_NOT_FINAL_ELIGIBILITY', 'records': records,
         'status_counts': dict(Counter(r['status'] for r in records)), 'minimum_installed_sources': plan['minimum_installed_sources'],
         'locked_names_at_least_30': sum(r.get('locked_name_pins', 0) >= 30 for r in records),
         'source_count_eligibility': 'NOT_MEASURED; requires captured installed metadata', 'model_calls': 0})


def capture(pool_root, resolution_root, out, workers):
    from sbom_recovery.capture import capture_cohort
    from sbom_recovery.budget_sources import prepare_catalog
    from sbom_recovery.contracts import TargetContext
    out.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(__file__, out / 'executed-runner.py')
    resolution = load(resolution_root / 'summary.json')
    resolve_plan = load(resolution_root / 'plan.json')
    if resolve_plan['pool_sha256'] != digest(pool_root / 'pool.json'):
        raise ValueError('Resolution pool changed')
    partition = resolve_plan['partition']
    pool_rows = {r.get('name'):r for r in load(pool_root / 'pool.json')['records'] if r.get('status')=='RELEASE_ELIGIBLE'}
    selected = []
    # Feasibility prescreen only. Installed catalog count, not lock count, determines eligibility.
    for result in resolution['records']:
        if result['status']!='RESOLVED' or result['locked_name_pins']<30:
            continue
        row=pool_rows[result['name']]
        selected.append({**row,**row['eligible'][partition],'partition':partition})
    config=load(ROOT/'configs/agent-recovery-v1.json')
    save(out/'capture-plan.json',{'schema_version':'fresh-source-feasibility-v1','projects':selected,'config':config,
         'pool_sha256':digest(pool_root/'pool.json'),'resolution_summary_sha256':digest(resolution_root/'summary.json'),
         'source_sha256':digest(__file__),'selection':'All resolved >=30-pin candidates in the frozen resolution prefix; no method outcomes',
         'is_final_cohort':False,'family_audit':'PENDING','security_stratum_audit':'NOT_RUN'})
    capture_root=out/'captures'
    summary=capture_cohort(out/'capture-plan.json',capture_root,workers=workers,source=False)
    records=[]
    for row in selected:
        folder=capture_root/row['name'];report=load(folder/'capture.json')
        record={'name':row['name'],'partition':partition,'build_status':report['status'],
                'capture_manifest_sha256':digest(folder/'capture.json'),'permitted_sources':None,'source_count_eligible':False}
        if report['status']=='COMPLETE':
            context=TargetContext.model_validate(load(folder/'context.json'))
            catalog=prepare_catalog(folder/'runtime/target',context,report['completed_at'])
            save(folder/'permitted-catalog.json',catalog)
            record.update(permitted_sources=len(catalog['sources']),source_count_eligible=len(catalog['sources'])>=32)
        records.append(record)
    save(out/'feasibility.json',{'status':'FEASIBILITY_COMPLETE','records':records,
         'attempted_builds':len(records),'successful_builds':summary['successful_builds'],
         'source_count_eligible':sum(r['source_count_eligible'] for r in records),'final_cohort':False,
         'predictions_run':False,'model_calls':0,'family_verification':'PENDING',
         'limitation':'Prescreen measures only the declared resolution prefix; lock-pin counts are not actual source counts'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['pool', 'resolve', 'capture'])
    parser.add_argument('--out', required=True)
    parser.add_argument('--pool')
    parser.add_argument('--resolution')
    parser.add_argument('--partition', choices=['development', 'calibration', 'test'], default='development')
    parser.add_argument('--limit', type=int, default=80)
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    if args.workers < 1 or args.workers > 12 or args.limit < 1:
        parser.error('Use 1–12 workers and a positive candidate limit')
    out = Path(args.out).resolve()
    if args.stage == 'pool':
        pool(out, args.workers)
    else:
        if not args.pool:
            parser.error('--pool is required')
        if args.stage=='resolve':
            resolve(Path(args.pool).resolve(), out, args.partition, args.limit, args.workers)
        else:
            if not args.resolution:parser.error('--resolution is required')
            capture(Path(args.pool).resolve(),Path(args.resolution).resolve(),out,args.workers)


if __name__ == '__main__':
    main()
