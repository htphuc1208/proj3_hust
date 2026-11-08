#!/usr/bin/env python3
"""Container-side independent installation of unchanged DSN author inputs."""
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent))
from benchmark import gold_from_inspect, as_cyclonedx


def run(entrypoint):
    out = Path('/out')
    records = []

    def execute(args):
        result = subprocess.run(args, text=True, capture_output=True, timeout=480)
        print(result.stdout, end='')
        print(result.stderr, end='', file=sys.stderr)
        records.append({'command': args, 'exit_code': result.returncode, 'completed_at': datetime.now(timezone.utc).isoformat()})
        (out / 'attempt_manifest.json').write_text(json.dumps(records, indent=2))
        if result.returncode:
            raise SystemExit(result.returncode)
        return result.stdout

    execute(['python', '-m', 'venv', '/tmp/independent'])
    target = '/tmp/independent/bin/python'
    execute([target, '-m', 'pip', 'install', '--report', '/out/installation.json', '-r', entrypoint])
    inspection = json.loads(execute([target, '-m', 'pip', 'inspect']))
    (out / 'pip_inspect.json').write_text(json.dumps(inspection, indent=2))
    execute([target, '-m', 'pip', 'check'])
    report = json.loads((out / 'installation.json').read_text())
    gold = gold_from_inspect(inspection, [], report, entrypoint)
    (out / 'ground_truth.json').write_text(json.dumps(gold, indent=2))
    (out / 'ground_truth.cdx.json').write_text(json.dumps(as_cyclonedx(gold), indent=2))


if __name__ == '__main__':
    run(sys.argv[1])
