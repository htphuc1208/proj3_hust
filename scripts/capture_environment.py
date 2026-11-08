#!/usr/bin/env python3
"""Container-side contemporary capture; no oracle is an input.

Resolution and installation read the same frozen artifact set, but the oracle is
collected independently from the installed environment, not the dry-run report.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from benchmark import gold_from_inspect, as_cyclonedx
from datetime import datetime, timezone


def utc():
    return datetime.now(timezone.utc).isoformat()


def capture(out, specifications):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    commands = []

    def execute(args, name):
        started = utc()
        t = time.monotonic()
        result = subprocess.run(args, capture_output=True, text=True, timeout=480)
        (out / (name + ".log")).write_text(result.stdout + result.stderr)
        commands.append({"name": name, "command": args, "started_at": started, "completed_at": utc(),
                         "latency_seconds": time.monotonic() - t, "exit_code": result.returncode})
        (out / "capture_manifest.json").write_text(json.dumps({"specifications": specifications, "commands": commands,
                   "status": "RUNNING" if not result.returncode else "BLOCKED"}, indent=2))
        if result.returncode:
            raise RuntimeError(name + " failed; see log")
        return result.stdout

    wheelhouse = out / "wheelhouse"
    wheelhouse.mkdir(exist_ok=True)
    execute(["python", "-m", "pip", "download", "--only-binary=:all:", "--dest", str(wheelhouse), *specifications], "download")
    wheel_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(wheelhouse.iterdir()) if p.is_file()}
    (out / "wheelhouse_manifest.json").write_text(json.dumps({"status": "PARTIAL_CANDIDATE_UNIVERSE", "artifacts": wheel_hashes}, indent=2))
    # B4 has no oracle mounts or files yet. Its complete input is public roots and the wheelhouse.
    execute(["python", "-m", "pip", "install", "--dry-run", "--ignore-installed", "--no-index", "--find-links", str(wheelhouse),
             "--report", str(out / "b4_resolution.json"), *specifications], "b4_dry_run")
    execute(["python", "-m", "venv", "/tmp/target"], "venv")
    target = "/tmp/target/bin/python"
    execute([target, "-m", "pip", "install", "--no-index", "--find-links", str(wheelhouse), "--report",
             str(out / "pip_install_report.json"), *specifications], "install")
    inspection = json.loads(execute([target, "-m", "pip", "inspect", "--local"], "inspect"))
    (out / "pip_inspect.json").write_text(json.dumps(inspection, indent=2))
    execute([target, "-m", "pip", "check"], "pip_check")
    report = json.loads((out / "pip_install_report.json").read_text())
    gold = gold_from_inspect(inspection, specifications, report, out.name)
    (out / "ground_truth.json").write_text(json.dumps(gold, indent=2))
    (out / "ground_truth.cdx.json").write_text(json.dumps(as_cyclonedx(gold), indent=2))
    execute(["cyclonedx-py", "environment", target, "--output-format", "JSON", "--output-file",
             str(out / "original.cdx.json")], "cyclonedx_scan")
    (out / "capture_manifest.json").write_text(json.dumps({"schema_version": "capture-manifest-v1", "status": "COMPLETE",
        "specifications": specifications, "commands": commands, "environment": inspection["environment"],
        "oracle_source": "Independent installed METADATA / pip inspect, not B4 report",
        "information_budget": "B4 sees manifest roots plus a frozen finite public artifact set", "wheelhouse_sha256":
        hashlib.sha256((out / "wheelhouse_manifest.json").read_bytes()).hexdigest()}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--spec", action="append", required=True)
    args = parser.parse_args()
    capture(args.out, args.spec)
