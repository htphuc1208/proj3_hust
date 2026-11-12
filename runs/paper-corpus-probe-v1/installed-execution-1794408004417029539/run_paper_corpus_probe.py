#!/usr/bin/env python3
"""Current-tool probes on DSN, Cofano and all ten published Python subjects.

Exploratory development evidence: preserves failures and information regimes.
Does not use the custom 20-project development cohort or its reference labels.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "research/.work/paper-corpus-probe-v1"
IMAGE = "sha256:805b20fa868a3c2fd8acec00101cf50c2b76314a540377ba081cac4b7c7ec907"
TOOL = ROOT / "research/.work/comparators/cyclonedx-python-8.0.1"
BUILD_IMAGE = IMAGE
BUILD_CONSTRAINT = None
RETRY_FAILED = False

PROBE = r'''
import importlib.metadata as m, json, os, platform, sys
v=sys.implementation.version
env=dict(os_name=os.name,sys_platform=sys.platform,platform_machine=platform.machine(),
 platform_system=platform.system(),platform_release=platform.release(),platform_version=platform.version(),
 python_version=".".join(platform.python_version_tuple()[:2]),python_full_version=platform.python_version(),
 implementation_name=sys.implementation.name,implementation_version="%s.%s.%s"%(v.major,v.minor,v.micro),
 platform_python_implementation=platform.python_implementation())
print(json.dumps(dict(environment=env,distributions=[dict(name=d.metadata['Name'],version=d.version,
 requirements=d.requires or [],metadata_path=str(d._path/'METADATA'),
 direct_url=json.loads(d.read_text('direct_url.json') or 'null')) for d in m.distributions()])))
'''


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def load(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def execute(command, out, label, timeout=180):
    started = time.monotonic()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as exc:
        code, stdout, stderr = 124, str(exc.stdout or ""), str(exc.stderr or "")
    (out / f"{label}.stdout").write_text(stdout)
    (out / f"{label}.stderr").write_text(stderr)
    record = dict(command=command, exit_code=code, seconds=time.monotonic() - started)
    save(out / f"{label}.execution.json", record)
    return record


def docker(source, out, *, network=False, target=None):
    command = ["docker", "run", "--rm", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--memory=2g", "--cpus=1", "--pids-limit=128", "--user", f"{os.getuid()}:{os.getgid()}",
        "-e", "PYTHONDONTWRITEBYTECODE=1", "-v", f"{source}:/source:ro", "-v", f"{out}:/out:rw",
        "-v", f"{TOOL}:/tool:ro", "--workdir", "/source"]
    if not network:
        command += ["--network", "none", "--read-only", "--tmpfs", "/tmp:rw,size=128m"]
    if target:
        command += ["-v", f"{target}:/target:ro"]
    return command


def cases():
    rows = []
    dsn = ROOT / "research/.work/sbom-benchmark"
    for name, path, entry in (("requirements", "req", "requirements.txt"), ("continuations", "req", "r.txt"),
                              ("poetry", "poetry", None), ("pipenv", "pipfile", None)):
        # Scanners never see author labels or a different requirements entrypoint.
        source = WORK / "dsn" / name
        source.mkdir(parents=True, exist_ok=True)
        files = [entry, "const.txt"] if entry else (["pyproject.toml"] if path == "poetry" else ["Pipfile"])
        if name == "requirements":
            files += ["otherreq.txt"]
            shutil.copytree(dsn / "python/req/downloads", source / "downloads", dirs_exist_ok=True)
        for file in files:
            shutil.copyfile(dsn / "python" / path / file, source / file)
        rows.append(dict(id="dsn/" + name, source=str(source), kind="dsn", entrypoint=entry,
            native="requirements" if entry else name,
            origin_commit=subprocess.check_output(["git", "-C", str(dsn), "rev-parse", "HEAD"], text=True).strip()))
    cofano = WORK / "cofano"
    commit = subprocess.check_output(["git", "-C", str(cofano), "rev-parse", "HEAD"], text=True).strip()
    for p in sorted((cofano / "projects").iterdir()):
        if not p.is_dir():
            continue
        native = "requirements" if (p / "requirements.txt").exists() else "pipenv" if (p / "Pipfile").exists() else "poetry" if p.name == "poetry-poetry" else None
        rows.append(dict(id="cofano/" + p.name, source=str(p), kind="cofano-pipenv" if native == "pipenv" else "cofano",
            entrypoint="requirements.txt" if native == "requirements" else None, native=native, origin_commit=commit))
    for r in csv.DictReader((ROOT / "research/.work/sbom-unifier-replication/subjects.csv").open()):
        if r["language"] == "python":
            acquisition = load(WORK / "real" / (r["project"] + ".acquisition.json"))
            rows.append(dict(id="real/" + r["project"], source=str(WORK / "real" / r["project"]),
                kind="real", native=None, entrypoint=None, origin_commit=acquisition.get("commit"),
                origin_url=r["url"], acquisition_exit_code=acquisition["exit_code"]))
    return rows


def source_scans(case, out):
    source = Path(case["source"])
    out.mkdir(parents=True, exist_ok=True)
    hashes = {str(p.relative_to(source)): sha(p) for p in source.rglob("*") if p.is_file() and ".git" not in p.parts}
    save(out / "input-manifest.json", {**case, "hashes": hashes})
    # Compact source snapshot for review; full source is bound by commit and file hashes.
    for name in ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "r.txt", "otherreq.txt", "const.txt", "Pipfile", "Pipfile.lock", "poetry.lock"):
        if (source / name).is_file():
            (out / "input").mkdir(exist_ok=True)
            shutil.copyfile(source / name, out / "input" / name)
    result = {}
    for tool in ("syft", "trivy"):
        if tool == "syft":
            command = [str(ROOT / "research/.work/syft"), "scan", "dir:" + str(source),
                "-o", "cyclonedx-json=" + str(out / "source-syft.cdx.json")]
        else:
            command = [str(ROOT / "research/.work/trivy"), "fs", "--offline-scan", "--skip-db-update",
                "--skip-java-db-update", "--disable-telemetry", "--skip-version-check", "--parallel", "1",
                "--format", "cyclonedx", "--output", str(out / "source-trivy.cdx.json"), str(source)]
        result[tool] = execute(command, out, "source-" + tool)
    native = case["native"]
    if native:
        args = ["-m", "cyclonedx_py", native]
        if native == "requirements":
            args += ["/source/" + case["entrypoint"]]
        elif native in ("poetry", "pipenv"):
            args += ["/source"]
        args += ["--output-reproducible", "--spec-version", "1.6", "--output-file", "/out/source-cyclonedx.cdx.json"]
        result["cyclonedx"] = execute(docker(source, out) + ["--entrypoint", "/tool/.venv/bin/python", IMAGE, *args], out, "source-cyclonedx")
    else:
        result["cyclonedx"] = dict(status="NO_NATIVE_SOURCE_MODE", note="No generic pyproject/setup.py source mode in this tool")
    save(out / "source-results.json", result)
    return dict(case=case["id"], phase="source", tools={k: v.get("exit_code", v.get("status")) for k, v in result.items()})


def installed_scans(case, out):
    if case["kind"] == "dsn" and not case["entrypoint"]:
        save(out / "build-result.json", dict(status="NOT_ATTEMPTED", reason="No root package; manifest parser fixture, no authored lockfile"))
        return dict(case=case["id"], phase="installed", status="NOT_ATTEMPTED")
    source, target = Path(case["source"]), out / "target"
    if RETRY_FAILED and (out / "build-result.json").exists() and load(out / "build-result.json")["status"] == "FAILED":
        archive = out / "attempts" / str(time.time_ns())
        archive.mkdir(parents=True)
        for pattern in ("build*", "wheel.*", "resolve.*", "install.*", "pip-check.*", "venv.*", "resolved.txt", "install.in", "pipenv-default-export.txt"):
            for path in out.glob(pattern):
                if path.is_file():
                    shutil.move(str(path), archive / path.name)
    if not (out / "build-result.json").exists():
        name = "sbom-paper-" + uuid.uuid4().hex
        cache = WORK / "uv-cache"
        cache.mkdir(exist_ok=True)
        cmd = docker(source, out, network=True)
        cmd += ["--name", name, "-e", "UV_CACHE_DIR=/cache", "-e", "UV_LINK_MODE=copy",
            "-v", f"{cache}:/cache:rw", "-v", f"{shutil.which('uv')}:/tools/uv:ro",
            "-v", f"{ROOT / 'scripts/paper_corpus_worker.py'}:/worker.py:ro"]
        if BUILD_CONSTRAINT:
            cmd += ["-v", f"{BUILD_CONSTRAINT}:/build-constraints.txt:ro", "-e", "UV_BUILD_CONSTRAINT=/build-constraints.txt"]
        cmd += ["--entrypoint", "python", BUILD_IMAGE, "/worker.py", "--kind", case["kind"]]
        if case["entrypoint"]:
            cmd += ["--entrypoint", case["entrypoint"]]
        try:
            execute(cmd, out, "build-container", timeout=900)
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        if not (out / "build-result.json").exists():
            save(out / "build-result.json", dict(status="FAILED", reason="Container failed or timed out"))
    build = load(out / "build-result.json")
    if build["status"] != "COMPLETE":
        return dict(case=case["id"], phase="installed", status=build["status"], reason=build.get("reason"))
    probe = execute(docker(source, out, target=target) + ["--entrypoint", "/target/bin/python", IMAGE,
        "-I", "-c", PROBE], out, "inventory")
    if probe["exit_code"]:
        return dict(case=case["id"], phase="installed", status="INVENTORY_FAILED")
    save(out / "inventory.json", load(out / "inventory.stdout"))
    results = {}
    for label, extra in (("environment", []), ("environment-pyproject", ["--pyproject", "/source/pyproject.toml"])):
        if extra and not (source / "pyproject.toml").exists():
            continue
        results[label] = execute(docker(source, out, target=target) + ["--entrypoint", "/tool/.venv/bin/python", IMAGE,
            "-m", "cyclonedx_py", "environment", "/target/bin/python", *extra, "--output-reproducible",
            "--spec-version", "1.6", "--output-file", f"/out/{label}.cdx.json"], out, label)
    for tool in ("syft", "trivy"):
        cmd = [str(ROOT / "research/.work/syft"), "scan", "dir:" + str(target), "-o", "cyclonedx-json=" + str(out / "installed-syft.cdx.json")] if tool == "syft" else [
            str(ROOT / "research/.work/trivy"), "rootfs", "--offline-scan", "--skip-db-update", "--skip-java-db-update",
            "--disable-telemetry", "--skip-version-check", "--parallel", "1", "--format", "cyclonedx", "--output",
            str(out / "installed-trivy.cdx.json"), str(target)]
        results[tool] = execute(cmd, out, "installed-" + tool)
    save(out / "installed-results.json", results)
    # Freeze observations before evaluation. The target itself stays in ignored storage.
    save(out / "prediction-seal.json", {p.name: sha(p) for p in out.glob("*.cdx.json")} |
         {"inventory.json": sha(out / "inventory.json")})
    return dict(case=case["id"], phase="installed", status="COMPLETE", tools={k: v["exit_code"] for k, v in results.items()})


def main():
    global BUILD_IMAGE, BUILD_CONSTRAINT, RETRY_FAILED
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--phase", choices=("source", "installed"), required=True)
    parser.add_argument("--build-image", default=IMAGE)
    parser.add_argument("--build-constraint", type=Path)
    parser.add_argument("--retry-failed", action="store_true")
    args = parser.parse_args()
    BUILD_IMAGE = args.build_image
    BUILD_CONSTRAINT = args.build_constraint.resolve() if args.build_constraint else None
    RETRY_FAILED = args.retry_failed
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    selected = cases()
    if not (out / "plan.json").exists():
        save(out / "plan.json", dict(cases=selected, image=IMAGE, cyclonedx="8.0.1", tools={
            n: sha(ROOT / "research/.work" / n) for n in ("syft", "trivy")},
            runtime="Linux Python 3.11.16", root_extras=[], network="Only acquisition/build may use network",
            per_wheel_limit_bytes=536870912, build_timeout_seconds=900,
            scope="Exploratory probes on paper artifacts; not a held-out study or exact historical reproduction"))
    assert selected == load(out / "plan.json")["cases"], "Frozen corpus changed"
    execution = out / (args.phase + "-execution-" + str(time.time_ns()))
    execution.mkdir()
    for script in (Path(__file__), ROOT / "scripts/paper_corpus_worker.py"):
        shutil.copyfile(script, execution / script.name)
    save(execution / "settings.json", dict(build_image=BUILD_IMAGE, retry_failed=RETRY_FAILED,
        build_constraint=BUILD_CONSTRAINT.read_text() if BUILD_CONSTRAINT else None))
    results = []
    function = source_scans if args.phase == "source" else installed_scans
    tasks = []
    with ThreadPoolExecutor(max_workers=3) as pool:
        for case in selected:
            case_out = out / case["id"]
            case_out.mkdir(parents=True, exist_ok=True)
            tasks.append(pool.submit(function, case, case_out))
        for future in as_completed(tasks):
            try:
                record = future.result()
            except Exception as exc:
                record = dict(status="EXECUTION_FAILED", reason=repr(exc))
            results.append(record)
            save(out / (args.phase + "-progress.json"), dict(completed=len(results), expected=len(selected), results=results))
            print(json.dumps(record), flush=True)
    save(out / (args.phase + "-summary.json"), dict(results=results, cases=len(selected)))


if __name__ == "__main__":
    main()
