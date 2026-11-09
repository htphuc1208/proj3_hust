"""Trusted container-side installation capture. Labels are generated after scanner inputs exist."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.request import urlopen
from packaging.tags import sys_tags
from packaging.utils import parse_wheel_filename
from packaging.utils import canonicalize_name

sys.path.insert(0, "/code")
from sbom_recovery.baselines.benchmark import gold_from_inspect, as_cyclonedx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True)
    parser.add_argument("--horizon", required=True)
    parser.add_argument('--no-time-limit', action='store_true')
    parser.add_argument('--freeze-wheels', action='store_true')
    parser.add_argument('--root-wheel')
    parser.add_argument('--root-sha256')
    args = parser.parse_args()
    out = Path("/out")
    log = []

    def execute(command, stage, timeout=240):
        started = time.monotonic()
        from datetime import datetime, timezone
        entry={'stage':stage,'command':command,'started_at':datetime.now(timezone.utc).isoformat(),'status':'RUNNING'}
        log.append(entry)
        (out/'commands.json').write_text(json.dumps(log,indent=2))
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=None if args.no_time_limit else timeout)
        except subprocess.TimeoutExpired as exc:
            captured=''.join(v.decode(errors='replace') if isinstance(v,bytes) else v or '' for v in [exc.stdout,exc.stderr])
            (out/(stage+'.log')).write_text(captured)
            entry.update(status='TIMEOUT',seconds=time.monotonic()-started)
            (out/'commands.json').write_text(json.dumps(log,indent=2))
            raise
        (out / (stage + ".log")).write_text(result.stdout + result.stderr)
        entry.update(status='COMPLETE' if not result.returncode else 'ERROR',exit_code=result.returncode,
                     seconds=time.monotonic()-started,completed_at=datetime.now(timezone.utc).isoformat())
        (out / "commands.json").write_text(json.dumps(log, indent=2))
        if result.returncode:
            raise RuntimeError(stage + " failed")
        return result.stdout
    (out / "root.in").write_text(args.spec + "\n")
    execute(["/tools/uv", "pip", "compile", "/out/root.in", "--python", sys.executable,
             "--exclude-newer", args.horizon, "--generate-hashes", "--only-binary", ":all:",
             "--default-index", "https://pypi.org/simple", "--cache-dir", "/cache/uv", "-o", "/out/requirements.lock"], "lock")
    if args.freeze_wheels:
        from wheel_acquisition import prepare_wheels
        if bool(args.root_wheel)!=bool(args.root_sha256):parser.error('Both root artifact fields are required together')
        artifact={'filename':args.root_wheel,'sha256':args.root_sha256} if args.root_wheel else None
        prepare_wheels(out/'requirements.lock',out,Path('/cache/frozen-wheels'),args.horizon,
                       root_name=canonicalize_name(args.spec.split('==')[0]),root_artifact=artifact)
    else:
        pins = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", (out / "requirements.lock").read_text(), re.M)
        tags = set(sys_tags())
        def wheel_size(pin):
            with urlopen(f"https://pypi.org/pypi/{pin[0]}/{pin[1]}/json", timeout=30) as response:
                payload = json.load(response)
            sizes = []
            for item in payload.get("urls", []):
                if not item["filename"].endswith(".whl"):
                    continue
                try:
                    if parse_wheel_filename(item["filename"])[3] & tags:
                        sizes.append(item["size"])
                except ValueError:
                    continue
            return min(sizes) if sizes else 0
        with ThreadPoolExecutor(max_workers=8) as pool:
            estimated = sum(pool.map(wheel_size, pins))
        (out / "size_estimate.json").write_text(json.dumps({"compressed_wheel_bytes": estimated}))
        if estimated > 536870912:
            raise RuntimeError("DECLARED_CAPTURE_SIZE_LIMIT_EXCEEDED")
    execute([sys.executable, "-m", "venv", "/out/target"], "venv")
    python = "/out/target/bin/python"
    # The lock already lists the complete resolved pins. check/inspect validate the installed environment.
    # Unrestricted collection need not invoke pip's resolver a second time.
    install_options=['--no-deps','--disable-pip-version-check'] if args.no_time_limit or args.freeze_wheels else []
    index_options=['--no-index','--find-links','/out/wheelhouse'] if args.freeze_wheels else ['--index-url','https://pypi.org/simple']
    execute([python, "-m", "pip", "install", *install_options, "--only-binary=:all:", "--require-hashes", *index_options,
             "--report", "/out/install_report.json", "-r", "/out/requirements.lock"], "install")
    execute([python, "-m", "pip", "check"], "pip_check")
    inspect = json.loads(execute([python, "-m", "pip", "inspect", "--local"], "inspect"))
    (out / "pip_inspect.json").write_text(json.dumps(inspect, indent=2))
    report = json.loads((out / "install_report.json").read_text())
    gold = gold_from_inspect(inspect, [args.spec], report, args.spec.split("==")[0])
    (out / "ground_truth.json").write_text(json.dumps(gold, indent=2))
    (out / "ground_truth.cdx.json").write_text(json.dumps(as_cyclonedx(gold), indent=2))
    labels = {row["name"]: row for row in gold["nodes"]}
    installed = {row["metadata"]["name"].lower().replace("_", "-"): row["metadata"] for row in inspect["installed"]}
    fields = {}
    for name, node in labels.items():
        fields[name] = {"name": name, "version": node["version"], "purl": node["purl"]}
        expression = installed.get(name, {}).get("license_expression")
        if expression:
            fields[name]["licenseDeclared"] = expression
    (out / "field_labels.json").write_text(json.dumps({"fields": fields, "provenance": "independent pip inspect",
             "unlabeled_fields": "UNKNOWN, not false", "license_scope": "distribution-declared license expression only"}, indent=2))


if __name__ == "__main__":
    main()
