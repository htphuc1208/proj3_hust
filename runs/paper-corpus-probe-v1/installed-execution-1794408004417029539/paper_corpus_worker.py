"""Networked, disposable build worker. No host credentials or reference labels."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", required=True)
    parser.add_argument("--entrypoint")
    args = parser.parse_args()
    out = Path("/out")
    source = Path("/tmp/paper-source")
    shutil.copytree("/source", source, ignore=shutil.ignore_patterns(".venv", "venv", "__pycache__"))
    steps = []

    def save(name, value):
        (out / name).write_text(json.dumps(value, indent=2) + "\n")

    def execute(label, command, timeout=240):
        started = time.monotonic()
        try:
            result = subprocess.run(command, cwd=source, text=True, capture_output=True, timeout=timeout)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as exc:
            code, stdout, stderr = 124, str(exc.stdout or ""), str(exc.stderr or "")
        (out / f"{label}.stdout").write_text(stdout)
        (out / f"{label}.stderr").write_text(stderr)
        steps.append(dict(step=label, command=command, exit_code=code, seconds=time.monotonic() - started))
        save("build-steps.json", steps)
        if code:
            raise RuntimeError(label)
        return stdout

    try:
        execute("venv", ["/tools/uv", "venv", "--python", sys.executable, "/out/target"])
        inputs = []
        if args.kind != "dsn":
            execute("wheel", ["/tools/uv", "build", "--wheel", "--python", sys.executable,
                "--out-dir", "/out/wheels", str(source)])
            wheels = sorted((out / "wheels").glob("*.whl"))
            if len(wheels) != 1:
                raise RuntimeError("EXPECTED_ONE_ROOT_WHEEL")
            inputs.append(str(wheels[0]))
        if args.entrypoint:
            inputs.append("-r " + str(source / args.entrypoint))
        elif args.kind == "cofano-pipenv":
            # A disclosed production-only export, not a claim to replay Pipenv itself.
            lock = json.loads((source / "Pipfile.lock").read_text())
            exported = []
            for name, row in sorted(lock["default"].items()):
                if row.get("git"):
                    url = row["git"]
                    url = url if url.startswith("git+") else "git+" + url
                    req = name + " @ " + url + "@" + row["ref"]
                elif row.get("file"):
                    req = name + " @ " + row["file"]
                else:
                    req = name + row["version"]
                if row.get("markers"):
                    req += "; " + row["markers"]
                exported.append(req)
            (out / "pipenv-default-export.txt").write_text("\n".join(exported) + "\n")
            inputs.append("-r /out/pipenv-default-export.txt")
        (out / "install.in").write_text("\n".join(inputs) + "\n")
        execute("resolve", ["/tools/uv", "pip", "compile", "/out/install.in", "--python-version", "3.11",
            "--no-annotate", "--output-file", "/out/resolved.txt"], timeout=300)
        # Avoid multi-GB CUDA downloads. This is a predeclared resource failure,
        # never a reason to substitute a different release or dependency graph.
        text = (out / "resolved.txt").read_text()
        torch = re.search(r"^torch==([^\s]+)", text, re.M)
        if torch:
            from pip._vendor.packaging.tags import sys_tags
            from pip._vendor.packaging.utils import parse_wheel_filename
            tags = set(sys_tags())
            url = "https://pypi.org/pypi/torch/" + torch[1] + "/json"
            payload = json.load(urllib.request.urlopen(url, timeout=30))
            compatible = [r for r in payload["urls"] if r["filename"].endswith(".whl")
                          and parse_wheel_filename(r["filename"])[3] & tags]
            save("large-wheel-check.json", {"package": "torch", "version": torch[1],
                "compatible_files": [{"filename": r["filename"], "bytes": r["size"]} for r in compatible],
                "per_wheel_limit_bytes": 536870912})
            if compatible and min(r["size"] for r in compatible) > 536870912:
                save("build-result.json", {"status": "RESOURCE_LIMIT", "reason": "torch wheel exceeds 512 MiB",
                    "steps": steps})
                return
        execute("install", ["/tools/uv", "pip", "install", "--python", "/out/target/bin/python",
            "-r", "/out/resolved.txt"], timeout=300)
        execute("pip-check", ["/tools/uv", "pip", "check", "--python", "/out/target/bin/python"])
        save("build-result.json", {"status": "COMPLETE", "steps": steps,
            "context": "Linux CPython 3.11.16; production base; no requested root extras",
            "selection": "current frozen source, current resolution; not historical installation replay"})
    except Exception as exc:
        save("build-result.json", {"status": "FAILED", "reason": str(exc), "steps": steps})


if __name__ == "__main__":
    main()
