"""Trusted, oracle-free preparation of a finite wheel set for a pinned build."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import threading
from urllib.parse import quote

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

try:
    from .artifact_cache import ArtifactCache, registry_json, utc
except ImportError:  # Standalone copy inside the pinned capture container.
    from artifact_cache import ArtifactCache, registry_json, utc


def instant(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Artifact timestamps require UTC offsets')
    return parsed


def lock_pins(text, environment=None):
    environment = environment or default_environment()
    records = {}
    for line in re.sub(r'\\\s*\n', ' ', text).splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        body, *options = line.split('--hash=')
        requirement = Requirement(body.strip())
        if requirement.marker and not requirement.marker.evaluate(environment):
            continue
        specs = list(requirement.specifier)
        hashes = {part.strip() for part in options}
        if (requirement.url or len(specs) != 1 or specs[0].operator != '==' or '*' in specs[0].version
                or not hashes or any(not re.fullmatch(r'sha256:[a-f0-9]{64}', value) for value in hashes)):
            raise ValueError('Build requires exact PyPI pins with SHA-256 hashes')
        name, version = canonicalize_name(requirement.name), specs[0].version
        if name in records:
            raise ValueError('Duplicate environment-applicable lock pin')
        records[name] = {'name': name, 'version': version, 'hashes': sorted(h[7:] for h in hashes)}
    if not records:
        raise ValueError('Empty applicable lock')
    return list(records.values())


def select_wheel(payload, pin, tags, horizon, python_version, root_artifact=None):
    ranks = {tag: i for i, tag in enumerate(tags)}
    choices = []
    for row in payload.get('urls', []):
        if row.get('packagetype') != 'bdist_wheel' or row.get('yanked'):
            continue
        filename = row['filename']
        try:
            name, version, build, wheel_tags = parse_wheel_filename(filename)
            timestamp = row.get('upload_time_iso_8601')
            if (canonicalize_name(name) != pin['name'] or version != Version(pin['version'])
                    or row['digests']['sha256'] not in pin['hashes'] or not timestamp
                    or instant(timestamp) > instant(horizon) or not set(wheel_tags) & ranks.keys()
                    or (row.get('requires_python') and Version(python_version) not in SpecifierSet(row['requires_python']))):
                continue
            if root_artifact and (filename != root_artifact['filename'] or row['digests']['sha256'] != root_artifact['sha256']):
                continue
            rank = min(ranks[tag] for tag in wheel_tags if tag in ranks)
            choices.append((rank, filename, row))
        except (ValueError, KeyError, TypeError):
            continue
    if not choices:
        raise ValueError('No hash-bound, compatible wheel available by horizon: ' + pin['name'])
    selected = min(choices, key=lambda c: (c[0], c[1]))[2]
    return {'name': pin['name'], 'version': pin['version'], 'filename': selected['filename'],
            'url': selected['url'], 'sha256': selected['digests']['sha256'], 'bytes': selected['size'],
            'uploaded_at': selected['upload_time_iso_8601']}


def prepare_wheels(lock, out, cache, horizon, *, root_name, root_artifact=None, max_bytes=536870912, workers=6):
    """Freeze compatible wheel choices, acquire verified bytes, return offline input.

    No installed-reference file exists or is read during this operation.
    max_bytes is a declared cohort size-eligibility condition, not an agent quota.
    """
    out, cache = Path(out), Path(cache)
    registry = out / 'artifact-registry'; registry.mkdir()
    guard = threading.Lock()
    def event(record):
        with guard:
            with (out / 'artifact-events.jsonl').open('a') as stream:
                stream.write(json.dumps(record) + '\n')
            (out / 'artifact-progress.json').write_text(json.dumps(record) + '\n')
    pins = lock_pins(Path(lock).read_text())
    tags = list(sys_tags())
    python_version = '.'.join(str(v) for v in sys.version_info[:3])
    def choose(pin):
        url = f"https://pypi.org/pypi/{quote(pin['name'],safe='')}/{quote(pin['version'],safe='')}/json"
        raw, payload = registry_json(url, on_event=event)
        path = registry / (pin['name'] + '.json'); path.write_bytes(raw)
        artifact = select_wheel(payload, pin, tags, horizon, python_version,
                                root_artifact if pin['name'] == root_name else None)
        artifact.update(registry_url=url, registry_sha256=hashlib.sha256(raw).hexdigest())
        return artifact
    with ThreadPoolExecutor(max_workers=workers) as pool:
        artifacts = list(pool.map(choose, pins))
    compressed = sum(row['bytes'] for row in artifacts)
    (out / 'size_estimate.json').write_text(json.dumps({'compressed_wheel_bytes': compressed,
         'basis': 'Exactly selected compatible wheel artifacts, not minimum over all versions/tags'}) + '\n')
    plan = {'schema_version': 'frozen-wheel-set-v1', 'lock_sha256': hashlib.sha256(Path(lock).read_bytes()).hexdigest(),
            'frozen_at': utc(), 'horizon': horizon, 'python_full_version': python_version,
            'wheel_tags': [str(t) for t in tags], 'artifacts': artifacts, 'compressed_bytes': compressed,
            'root_artifact_binding': root_artifact, 'reference_labels_read': False}
    (out / 'artifact-plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    if max_bytes is not None and compressed > max_bytes:
        raise ValueError('DECLARED_CAPTURE_SIZE_LIMIT_EXCEEDED')
    store = ArtifactCache(cache, on_event=event)
    def obtain(row):
        return store.obtain(url=row['url'], sha256=row['sha256'], size=row['bytes'], filename=row['filename'])
    with ThreadPoolExecutor(max_workers=workers) as pool:
        receipts = list(pool.map(obtain, artifacts))
    wheelhouse = out / 'wheelhouse'; wheelhouse.mkdir()
    for record in receipts:
        (wheelhouse / record['filename']).symlink_to(record['path'])
    (out / 'artifact-receipts.json').write_text(json.dumps({'artifacts': receipts, 'verified_at': utc()}, indent=2) + '\n')
    return wheelhouse
