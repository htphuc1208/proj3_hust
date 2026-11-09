#!/usr/bin/env python3
"""Offline-capable, independent PyPI installed-metadata benchmark builder.

NOT a dependency resolver and NOT evidence of executed-code reachability.
Never feeds gold metadata to an evaluated reconstruction model.
"""
from __future__ import annotations
import argparse
from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import csv
import json
from pathlib import Path
import shutil
import subprocess
import sys

from packaging.requirements import Requirement
from packaging.markers import default_environment
from packaging.utils import canonicalize_name
from packaging.version import Version, InvalidVersion


def load(p):
    return json.loads(Path(p).read_text(encoding='utf-8'))


def save(p, data):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + '\n', encoding='utf-8')


def digest(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def score(truth, observed):
    tp = len(truth & observed)
    fp = len(observed - truth)
    fn = len(truth - observed)
    return {'tp': tp, 'fp': fp, 'fn': fn,
            'precision': tp/(tp+fp) if tp+fp else None,
            'recall': tp/(tp+fn) if tp+fn else None,
            'f1': (2*tp)/(2*tp+fp+fn) if (2*tp+fp+fn) else None}


def marker_active(req, environment, extras):
    """PEP 508 marker evaluation; handle base and activated extras.

    Returns (active, evidence contexts). Each extra is evaluated separately.
    """
    if req.marker is None:
        return True, ['unconditional']
    contexts = [''] + sorted(extras)
    activated = []
    for extra in contexts:
        e = {**environment, 'extra': extra}
        try:
            ok = req.marker.evaluate(environment=e, context='metadata')
        except TypeError:  # packaging older versions
            ok = req.marker.evaluate(environment=e)
        if ok:
            activated.append('base' if not extra else f'extra:{extra}')
    return bool(activated), activated


def installed_index(inspect):
    if inspect.get('version') != '1':
        raise ValueError('Unsupported pip inspect format version (expected 1)')
    index = {}
    for item in inspect.get('installed', []):
        m = item.get('metadata') or {}
        if not m.get('name') or not m.get('version'):
            continue
        name = canonicalize_name(m['name'])
        if name in index:
            raise ValueError(f'Duplicate installed normalized package: {name}')
        index[name] = item
    return index


def parse_roots(roots, report, index):
    """Explicit roots preferred; report.requested_extras only for top-level roots."""
    parsed = {}
    for s in roots:
        r = Requirement(s)
        n = canonicalize_name(r.name)
        if n not in index:
            raise ValueError(f'Root is not installed: {n}')
        if r.specifier and not r.specifier.contains(index[n]['metadata']['version'], prereleases=True):
            raise ValueError(f'Root version does not satisfy input: {s}')
        parsed.setdefault(n, set()).update(canonicalize_name(x) for x in r.extras)
    if report:
        if report.get('version') != '1':
            raise ValueError('Unsupported installation report version')
        for row in report.get('install', []):
            if not row.get('requested'):
                continue
            m = row.get('metadata') or {}
            if not m.get('name'):
                continue
            n = canonicalize_name(m['name'])
            # Only use report entries for matching roots, or infer roots if none provided.
            if roots and n not in parsed:
                continue
            if n in index and m.get('version') != index[n]['metadata'].get('version'):
                raise ValueError(f'Install report/inspect mismatch for requested {n}')
            if n in index:
                parsed.setdefault(n, set()).update(canonicalize_name(x) for x in row.get('requested_extras', []))
    if not parsed:
        raise ValueError('Supply at least one --root or a matching installation report with requested packages')
    return parsed


def gold_from_inspect(inspect, roots, report=None, project='benchmark-project'):
    """Reconstruct direct declared requirements within the installed resolved set.

    Cannot infer unrecorded extras, runtime imports, wheel contents, or build-time deps.
    """
    index = installed_index(inspect)
    environment = inspect.get('environment') or {}
    if not environment:
        raise ValueError('pip inspect has no environment: cannot safely evaluate PEP 508')
    active_extras = parse_roots(roots, report, index)
    root_names = set(active_extras)
    queue = deque(sorted(root_names))
    traversed = {}
    edge_reasons = defaultdict(set)
    warnings = []
    unresolved = []
    evaluated_requirements = 0
    while queue:
        parent = queue.popleft()
        extras = frozenset(active_extras[parent])
        if traversed.get(parent) == extras:
            continue
        traversed[parent] = extras
        parent_metadata = index[parent]['metadata']
        for raw in parent_metadata.get('requires_dist', []) or []:
            evaluated_requirements += 1
            try:
                r = Requirement(raw)
                active, reasons = marker_active(r, environment, extras)
            except Exception as e:
                unresolved.append({'parent': parent, 'requirement': raw, 'reason': 'invalid-requirement-or-marker', 'details': str(e)})
                continue
            if not active:
                continue
            child = canonicalize_name(r.name)
            if child not in index:
                unresolved.append({'parent': parent, 'requirement': raw, 'child': child, 'reason': 'activated-requirement-not-installed'})
                continue
            installed_version = index[child]['metadata']['version']
            try:
                valid = not r.specifier or r.specifier.contains(installed_version, prereleases=True)
            except (ValueError, InvalidVersion):
                valid = False
            if not valid:
                unresolved.append({'parent': parent, 'requirement': raw, 'child': child, 'installed_version': installed_version,
                                   'reason': 'installed-version-violates-requirement'})
                continue
            edge_reasons[(parent, child)].update(f'{raw} ({context})' for context in reasons)
            extras_next = set(canonicalize_name(x) for x in r.extras)
            if child not in active_extras:
                active_extras[child] = extras_next
                queue.append(child)
            elif not extras_next.issubset(active_extras[child]):
                active_extras[child].update(extras_next)
                queue.append(child)
    # Even if child had a metadata error, keep it in the eligible node set when reached.
    reached = set(active_extras)
    if any(x['reason'] in ('invalid-requirement-or-marker', 'installed-version-violates-requirement',
                          'activated-requirement-not-installed') for x in unresolved):
        warnings.append('Incomplete/inconsistent install metadata: do not treat absent edges as verified negatives')
    if report is None:
        warnings.append('No pip install --report; roots/extras only from --root, possible loss of top-level extras provenance')
    else:
        report_env = report.get('environment', {})
        for k in ('python_version', 'sys_platform', 'platform_machine'):
            if k in report_env and k in environment and report_env[k] != environment[k]:
                warnings.append(f'Install-report context differs on {k}: {report_env[k]} != {environment[k]}')
    nodes = []
    for n in sorted(reached):
        m = index[n]['metadata']
        nodes.append({'name': n, 'version': m['version'], 'purl': f'pkg:pypi/{n}@{m["version"]}',
                      'requested_extras': sorted(active_extras[n]),
                      'requested_root': n in root_names})
    edges = [{'from': a, 'to': b, 'evidence': sorted(reasons)}
             for (a,b), reasons in sorted(edge_reasons.items()) if a in reached and b in reached]
    result = {
        'schema_version': 'benchmark-v1',
        'project': project,
        'semantics': 'direct Requires-Dist dependency graph of installed distributions, projected onto requested roots and known extras',
        'roots': sorted(root_names), 'context': environment, 'nodes': nodes, 'edges': edges,
        'unresolved': unresolved, 'warnings': warnings,
        'counts': {'packages': len(nodes), 'direct_package_edges': len(edges), 'evaluated_requirement_records': evaluated_requirements,
                   'unresolved': len(unresolved)}
    }
    return result


def as_cyclonedx(gold):
    ref = {n['name']: n['purl'] for n in gold['nodes']}
    outgoing = defaultdict(list)
    for e in gold['edges']:
        outgoing[e['from']].append(ref[e['to']])
    root_ref = f'urn:sbom-benchmark:project:{gold["project"]}'
    deps = [{'ref': root_ref, 'dependsOn': sorted(ref[n] for n in gold['roots'])}]
    for n in sorted(ref):
        deps.append({'ref': ref[n], 'dependsOn': sorted(set(outgoing[n]))})
    return {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
        'metadata': {'component': {'type': 'application', 'name': gold['project'], 'version': '0', 'bom-ref': root_ref}},
        'components': [{'type': 'library', 'name': n['name'], 'version': n['version'], 'purl': n['purl'],
                        'bom-ref': n['purl']} for n in gold['nodes']],
        'dependencies': deps
    }


def pkg_graph_from_cdx(sbom):
    nodes_by_ref = {}
    ambiguous = []
    root_comp = sbom.get('metadata', {}).get('component') or {}
    root_ref = root_comp.get('bom-ref')
    root_ident = ("__ROOT__", root_comp.get('name', 'project'))

    for comp in sbom.get('components', []):
        purl = comp.get('purl') or ''
        if not purl.startswith('pkg:pypi/') or '@' not in purl:
            continue
        name, version = purl[len('pkg:pypi/'):].split('?',1)[0].split('#',1)[0].rsplit('@',1)
        try:
            n = canonicalize_name(name)
        except Exception:
            continue
        node = (n, version)
        ref = comp.get('bom-ref')
        if not ref:
            continue
        if ref in nodes_by_ref and nodes_by_ref[ref] != node:
            ambiguous.append(ref)
        nodes_by_ref[ref] = node

    nodes = set(nodes_by_ref.values())
    pkg_edges = set()
    root_edges = set()
    dangling = 0
    for entry in sbom.get('dependencies', []):
        src_ref = entry.get('ref')
        is_root = (src_ref == root_ref or (src_ref and 'project' in src_ref.lower()))
        frm = root_ident if is_root else nodes_by_ref.get(src_ref)
        for target in entry.get('dependsOn', []):
            to = nodes_by_ref.get(target)
            if to is None:
                dangling += 1
            elif is_root:
                root_edges.add(to)
            elif frm is not None:
                pkg_edges.add((frm, to))
            else:
                dangling += 1
    return nodes, pkg_edges, root_edges, {'dangling_or_nonpypi_edges': dangling, 'ambiguous_refs': ambiguous}


def compare_graphs(truth, observed):
    tn, te, tr, tw = pkg_graph_from_cdx(truth)
    on, oe, oroot, ow = pkg_graph_from_cdx(observed)
    return {
        'semantics': 'PyPI component and direct-dependency overlap; scope mismatches are discrepancies, not automatically generator faults',
        'truth': {'nodes': len(tn), 'package_edges': len(te), 'root_edges': len(tr), **tw},
        'observed': {'nodes': len(on), 'package_edges': len(oe), 'root_edges': len(oroot), **ow},
        'component_overlap': score(tn, on),
        'edge_overlap': score(te, oe),  # pure package-to-package edges
        'root_edge_overlap': score(tr, oroot),  # root-to-direct package dependencies
        'missing_components': sorted(f'{n}@{v}' for n, v in tn - on),
        'extra_components': sorted(f'{n}@{v}' for n, v in on - tn),
        'missing_package_edges': sorted(f'{a}@{av} -> {b}@{bv}' for (a, av), (b, bv) in te - oe),
        'extra_package_edges': sorted(f'{a}@{av} -> {b}@{bv}' for (a, av), (b, bv) in oe - te),
        'missing_root_edges': sorted(f'ROOT -> {n}@{v}' for n, v in tr - oroot),
        'extra_root_edges': sorted(f'ROOT -> {n}@{v}' for n, v in oroot - tr),
    }


def build(args):
    inp = Path(args.inspect)
    report = load(args.install_report) if args.install_report else None
    gold = gold_from_inspect(load(inp), args.root, report, args.project)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    save(out/'ground_truth.json', gold)
    save(out/'ground_truth.cdx.json', as_cyclonedx(gold))
    save(out/'provenance.json', {
        'project': args.project, 'inputs': {'pip_inspect_sha256': digest(inp),
        'pip_install_report_sha256': digest(args.install_report) if args.install_report else None},
        'root_requirements': args.root, 'pip_inspect_pip_version': load(inp).get('pip_version'),
        'time_utc': datetime.now(timezone.utc).isoformat(),
        'warning': 'Reference describes a concrete installed Python environment, not actual runtime calls or shipped binary contents',
    })
    print(json.dumps({'output': str(out), **gold['counts'], 'warnings': gold['warnings']}, indent=2))


def collect(args):
    p = Path(args.out)
    p.mkdir(parents=True, exist_ok=True)
    python = args.python
    venv_result = subprocess.run([python, '-c',
        'import sys,json;print(json.dumps({"executable":sys.executable,"prefix":sys.prefix,"base_prefix":sys.base_prefix}))'],
        capture_output=True, text=True, check=True)
    interpreter = json.loads(venv_result.stdout)
    if interpreter['prefix'] == interpreter['base_prefix'] and not args.allow_shared_env:
        raise ValueError('Target interpreter is not a venv; use isolated venv or --allow-shared-env (pilot only)')
    inspect_proc = subprocess.run([python,'-m','pip','inspect','--local'],capture_output=True,text=True, check=True)
    inspect_path = p/'pip_inspect.json'
    inspect_path.write_text(inspect_proc.stdout,encoding='utf-8')
    check_proc = subprocess.run([python,'-m','pip','check'], capture_output=True,text=True)
    (p/'pip_check.txt').write_text(check_proc.stdout+check_proc.stderr,encoding='utf-8')
    if args.install_report:
        src_report = Path(args.install_report).resolve()
        dst_report = (p / 'pip_install_report.json').resolve()
        if src_report != dst_report:
            shutil.copyfile(src_report, dst_report)
    save(p/'capture_metadata.json', {'interpreter': interpreter, 'pip_check_exit_code':check_proc.returncode,
        'isolated_venv': interpreter['prefix'] != interpreter['base_prefix'],
        'preliminary_capture_gates_passed': (interpreter['prefix'] != interpreter['base_prefix'] and check_proc.returncode == 0 and bool(args.install_report)),
        'installed_report_provided': bool(args.install_report),
        'requested_root_requirements': args.root,
        'caution':'Pip check validates installed requirement consistency, not exact extras provenance or runtime reachability'})
    b = argparse.Namespace(inspect=inspect_path,
        install_report=(p/'pip_install_report.json') if args.install_report else None,
        project=args.project, root=args.root, out=p)
    build(b)
    if check_proc.returncode != 0:
        print('WARNING: pip check nonzero; do not use this environment as clean reference', file=sys.stderr)


def compare(args):
    results = compare_graphs(load(args.truth), load(args.observed))
    save(args.out, results)
    print(json.dumps({'output': str(args.out), 'nodes': results['component_overlap'], 'edges': results['edge_overlap']}, indent=2))



def batch(args):
    """Process pre-collected pip inspect snapshots; does not install untrusted projects."""
    manifest_path = Path(args.manifest).resolve()
    manifest = load(manifest_path)
    projects = manifest.get('projects')
    if not isinstance(projects,list) or not projects:
        raise ValueError('Manifest needs nonempty projects list')
    seen = set()
    base = manifest_path.parent
    output = Path(args.out)
    rows = []
    for item in projects:
        project = item['id']
        if project in seen:
            raise ValueError(f'Duplicate project id: {project}')
        seen.add(project)
        try:
            src = (base / item['inspect_path']).resolve()
            report = (base / item['install_report_path']).resolve() if item.get('install_report_path') else None
            data = gold_from_inspect(load(src), item.get('roots', []), load(report) if report else None, project)
            dst = output / project
            dst.mkdir(parents=True, exist_ok=True)
            save(dst/'ground_truth.json',data)
            save(dst/'ground_truth.cdx.json',as_cyclonedx(data))
            save(dst/'provenance.json', {'project':project,
                'repo_url':item.get('repo_url'), 'commit_sha':item.get('commit_sha'),
                'python_version': data['context'].get('python_version'),
                'pip_inspect_sha256':digest(src),
                'install_report_sha256':digest(report) if report else None,
                'has_install_report':bool(report),
                'warning':'Record exact container digest and installation command independently'})
            status = 'needs_review' if data['unresolved'] or not report else 'collected'
            rows.append({'project':project,'status':status, 'nodes':len(data['nodes']),
                         'edges':len(data['edges']),'unresolved':len(data['unresolved']),
                         'has_report':bool(report), 'error':''})
        except Exception as e:
            rows.append({'project':project,'status':'failed', 'nodes':0,'edges':0,'unresolved':0,
                         'has_report':False,'error':str(e)})
    output.mkdir(parents=True, exist_ok=True)
    save(output/'batch_summary.json', {'projects':rows,
        'warning':'Collection statuses do not certify reproducibility; audit commits, image digests, installation logs and pip check'})
    with (output/'batch_summary.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f, fieldnames=['project','status','nodes','edges','unresolved','has_report','error'])
        writer.writeheader();writer.writerows(rows)
    print(json.dumps({'output':str(output),'projects':len(rows),'collected':sum(x['status']=='collected' for x in rows),
                      'needs_review':sum(x['status']=='needs_review' for x in rows),
                      'failed':sum(x['status']=='failed' for x in rows)},indent=2))


def main():
    p = argparse.ArgumentParser(description='SBOM benchmark harness v1: independent installed Python metadata reference')
    sp = p.add_subparsers(dest='cmd', required=True)
    b = sp.add_parser('build', help='Offline processing from pip inspect output')
    b.add_argument('--inspect', required=True, type=Path)
    b.add_argument('--install-report', type=Path)
    b.add_argument('--project', required=True)
    b.add_argument('--root', action='append', default=[], help='e.g. requests[socks]==2.31.0; repeat for multiple roots')
    b.add_argument('--out', required=True, type=Path)
    b.set_defaults(run=build)
    c = sp.add_parser('collect', help='Inspect an already-installed Python venv; no installs performed')
    c.add_argument('--python', required=True)
    c.add_argument('--project', required=True)
    c.add_argument('--root', action='append', default=[])
    c.add_argument('--install-report', type=Path)
    c.add_argument('--out', required=True, type=Path)
    c.add_argument('--allow-shared-env', action='store_true', help='pilot/debug only; benchmark requires isolated venv')
    c.set_defaults(run=collect)
    d = sp.add_parser('compare', help='Compare a real generator SBOM to reference PyPI graph')
    d.add_argument('--truth', required=True, type=Path)
    d.add_argument('--observed', required=True, type=Path)
    d.add_argument('--out', required=True, type=Path)
    d.set_defaults(run=compare)
    bb = sp.add_parser('batch', help='Build multiple independent references from recorded inspect snapshots')
    bb.add_argument('--manifest', required=True, type=Path)
    bb.add_argument('--out', required=True, type=Path)
    bb.set_defaults(run=batch)
    args = p.parse_args()
    args.run(args)


if __name__ == '__main__':
    main()
