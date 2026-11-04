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

sys.path.insert(0, "/code")
from benchmark import gold_from_inspect, as_cyclonedx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True)
    parser.add_argument("--horizon", required=True)
    args = parser.parse_args()
    out = Path("/out")
    log = []

    def execute(command, stage, timeout=240):
        started = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        (out / (stage + ".log")).write_text(result.stdout + result.stderr)
        log.append({"stage": stage, "command": command, "exit_code": result.returncode,
                    "seconds": time.monotonic() - started})
        (out / "commands.json").write_text(json.dumps(log, indent=2))
        if result.returncode:
            raise RuntimeError(stage + " failed")
        return result.stdout
    (out / "root.in").write_text(args.spec + "\n")
    execute(["/tools/uv", "pip", "compile", "/out/root.in", "--python", sys.executable,
             "--exclude-newer", args.horizon, "--generate-hashes", "--only-binary", ":all:",
             "--default-index", "https://pypi.org/simple", "--cache-dir", "/cache/uv", "-o", "/out/requirements.lock"], "lock")
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
    execute([python, "-m", "pip", "install", "--only-binary=:all:", "--require-hashes", "--index-url", "https://pypi.org/simple",
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
