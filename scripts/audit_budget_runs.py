#!/usr/bin/env python3
"""Audit sealed budget episodes without target files, references or model calls."""
import argparse
from hashlib import sha256
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research_core import load, digest
from sbom_recovery.contracts import TargetContext
from sbom_recovery.formats import sha, validate_native
from sbom_recovery.selective_gate import gate
from sbom_recovery.storage import save


def audit(episode, replay=False, allow_missing_runtime=False):
    worker = episode / 'execution/worker'
    seal = load(worker / 'seal.json')
    result, state, trace = (load(worker / name) for name in ('result.json', 'state.json', 'trace.json'))
    observation, context, catalog = (load(episode / name) for name in ('observation.json', 'context.json', 'catalog.json'))
    for key, value in [('input', observation), ('context', context), ('result', result),
                       ('prediction', result['document']), ('state', state), ('trace', trace)]:
        if sha(value) != seal[key + '_sha256']:
            raise ValueError('Changed sealed ' + key)
    if catalog['sha256'] != seal['catalog_sha256']:
        raise ValueError('Catalog binding changed')
    acquired = {p.name: p.read_bytes() for p in (worker / 'acquired').iterdir()} if (worker / 'acquired').exists() else {}
    if {k: sha256(v).hexdigest() for k, v in acquired.items()} != seal['acquired']:
        raise ValueError('Acquired bytes changed')
    if set(acquired) != set(state['acquired_source_ids']):
        raise ValueError('Acquired state mismatch')
    reader = load(episode / 'controller-reader-audit.json')
    rpc = load(episode / 'execution/reader-audit.json')
    if not (len(acquired) <= reader['source_content_reads'] <= rpc['source_requests'] <= state['attempts']):
        raise ValueError('Acquisition budget accounting mismatch')
    if state['budget'] is not None and state['attempts'] > state['budget']:
        raise ValueError('Acquisition quota exceeded')
    if (sum(len(v) for v in acquired.values()) > state['bytes_read']
            or (state['byte_budget'] is not None and state['bytes_read'] > state['byte_budget'])):
        raise ValueError('Byte budget accounting mismatch')
    runtime_path = episode / 'execution/runtime-boundary.json'
    runtime = load(runtime_path) if runtime_path.is_file() else None
    if runtime is None and not allow_missing_runtime:
        raise ValueError('Missing contemporaneous runtime inspection')
    if runtime is not None and (set(runtime['mounts']) - {'/code', '/input', '/out', '/tmp'}
            or runtime['mounts']['/code']['rw'] or runtime['mounts']['/input']['rw']
            or runtime['network'] != 'none' or not runtime['read_only_root']
            or 'NETMIND_API_KEY' in runtime['environment_variable_names']):
        raise ValueError('Runtime isolation mismatch')
    if validate_native(result['document'])['valid'] != result['validation']['valid']:
        raise ValueError('Native validity changed')
    equivalent = None
    if replay:
        current = gate(observation, TargetContext.model_validate(context), catalog, acquired)
        equivalent = sha(current['document']) == seal['prediction_sha256']
        if not equivalent:
            raise ValueError('Current gate changes this frozen source plan')
    return {'episode': str(episode.relative_to(ROOT)), 'seal_sha256': digest(worker / 'seal.json'),
            'native_valid': result['validation']['valid'], 'runtime_isolation_verified': True if runtime else None,
            'attempts': state['attempts'], 'budget': state['budget'], 'acquired_sources': len(acquired),
            'replayed_with_current_gate': replay, 'prediction_equivalent': equivalent}


def main():
    source_digest = digest(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--roots', nargs='+', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--replay', action='store_true')
    parser.add_argument('--allow-missing-runtime', action='store_true',
                        help='Retain older runs with runtime verification explicitly unknown')
    args = parser.parse_args()
    out = Path(args.out)
    if out.exists():
        raise FileExistsError(out)
    episodes = sorted({p.parent.parent.parent for root in args.roots
                       for p in Path(root).glob('**/execution/worker/seal.json')})
    if not episodes:
        raise ValueError('No sealed episodes')
    rows = [audit(p.resolve(), args.replay, args.allow_missing_runtime) for p in episodes]
    status = 'VERIFIED' if all(r['runtime_isolation_verified'] for r in rows) else 'SEALS_VERIFIED_RUNTIME_PARTIAL'
    save(out, {'status': status,
               'episodes': len(rows), 'records': rows,
               'audit_source_sha256': source_digest, 'target_files_read': False,
               'reference_files_read': False, 'model_calls': 0})
    print(f'{status}: {len(rows)} sealed episodes')


if __name__ == '__main__':
    main()
