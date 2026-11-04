"""Pinned builds and scanner capture; a separate evaluator owns oracle files."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import time

from container_runner import run_container
from research_core import digest, load, now, save
from .formats import sha
from .storage import save

ROOT = Path(__file__).resolve().parents[1]


def command(args, logfile, timeout=240):
    started = time.monotonic()
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        text = result.stdout + result.stderr
        code = result.returncode
    except subprocess.TimeoutExpired:
        text, code = "TIMEOUT", 124
    Path(logfile).write_text(text)
    return {"command": args, "exit_code": code, "seconds": time.monotonic() - started}


def capture_project(row, destination, protocol, image, source=True):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    manifest_path = destination / "capture.json"
    if manifest_path.exists():
        prior = load(manifest_path)
        if prior.get("status") == "COMPLETE":
            return prior
    oracle = destination / "oracle"
    oracle.mkdir(exist_ok=True)
    runtime = destination / "runtime"
    runtime.mkdir(exist_ok=True)
    code = destination.parent / "capture_code"
    code.mkdir(exist_ok=True)
    # Identical bytes are safe to write once by the parent runner before workers start.
    cache = ROOT / "research/.work/m25-capture-cache"
    cache.mkdir(parents=True, exist_ok=True)
    horizon = protocol["partitions"][row["partition"]]["end"]
    args = ["docker", "run", "--rm", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=2g",
            "--cpus=1", "--pids-limit=128", "--user", f"{os.getuid()}:{os.getgid()}",
            "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "UV_CACHE_DIR=/cache/uv", "-e", "XDG_CACHE_HOME=/cache",
            "-v", f"{code}:/code:ro", "-v", f"{shutil.which('uv')}:/tools/uv:ro", "-v", f"{cache}:/cache:rw",
            "-v", f"{runtime}:/out:rw", "--entrypoint", "python", image, "/code/capture_worker.py",
            "--spec", row["name"] + "==" + row["version"], "--horizon", horizon]
    started = now()
    try:
        result = run_container(args, timeout=900)
        (destination / "container.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("INSTALL_CAPTURE_FAILED")
        # Move labels/build reports outside every inference input mount.
        for name in ("ground_truth.json", "ground_truth.cdx.json", "field_labels.json", "pip_inspect.json",
                     "install_report.json", "requirements.lock", "root.in", "commands.json"):
            if (runtime / name).exists():
                shutil.move(str(runtime / name), oracle / name)
        inspection = load(oracle / "pip_inspect.json")
        actual_env = inspection["environment"]
        if actual_env["python_full_version"] != protocol["target"]["python_full_version"]:
            raise RuntimeError("TARGET_INTERPRETER_MISMATCH")
        metadata = sorted((runtime / "target").rglob("*.dist-info/METADATA"))
        target_id = sha([(str(p.relative_to(runtime / "target")), digest(p)) for p in metadata])
        ctx = {**protocol["target"], "target_id": target_id,
               "evidence_cutoff": now(), "extras_by_purl": {},
               "root_purls": [f"pkg:pypi/{row['name']}@{row['version']}"]}
        save(destination / "context.json", ctx)
        scans = {}
        syft, trivy = ROOT / "research/.work/syft", ROOT / "research/.work/trivy"
        for tool, exe, arguments in (
            ("syft", syft, ["scan", "dir:" + str(runtime / "target"), "-o", "spdx-json=" + str(runtime / "syft.spdx.json"),
                             "-o", "cyclonedx-json=" + str(runtime / "syft.cdx.json")]),
            ("trivy", trivy, ["rootfs", "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--format", "spdx-json",
                              "--output", str(runtime / "trivy.spdx.json"), str(runtime / "target")])):
            if not exe.exists():
                scans[tool] = {"status": "TOOL_UNAVAILABLE"}
            else:
                stat = command([str(exe), *arguments], destination / (tool + ".log"), timeout=180)
                scans[tool] = {**stat, "binary_sha256": digest(exe), "scope": "installed filesystem"}
        # A root declaration is build input, not an inferred oracle version.
        # Keep raw generator outputs untouched; root identity is provided separately.
        source_state = {"status": "NOT_REQUESTED"}
        if source:
            source_state = checkout_source(row, destination / "source", horizon)
            if source_state["status"] == "CHECKED_OUT":
                src = destination / "source"
                for tool, exe, arguments in (
                    ("syft", syft, ["scan", "dir:" + str(src), "-o", "spdx-json=" + str(runtime / "source-syft.spdx.json")]),
                    ("trivy", trivy, ["fs", "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--format", "spdx-json",
                                      "--output", str(runtime / "source-trivy.spdx.json"), str(src)])):
                    if exe.exists():
                        scans["source-" + tool] = command([str(exe), *arguments], destination / ("source-" + tool + ".log"), 180)
                ms = ROOT / "research/.work/sbom-tool"
                if ms.exists():
                    msout = runtime / "source-ms"
                    msout.mkdir(exist_ok=True)
                    scans["source-ms"] = command([str(ms), "generate", "-b", str(src), "-bc", str(src),
                        "-m", str(msout), "-pn", row["name"], "-pv", row["version"], "-ps", row["repository"].split('/')[0],
                        "-nsb", "https://sbom-recovery.local/" + row["name"], "-D", "true"], destination / "source-ms.log", 180)
        report = {"schema_version": "capture-v1", "status": "COMPLETE", "project": row,
                  "started_at": started, "completed_at": now(), "image": image, "container_command": args,
                  "historical_resolution_horizon": horizon, "installation_kind": "RETROSPECTIVE_PINNED_PYPI_WHEEL_BUILD",
                  "target_id": target_id, "source": source_state, "scanners": scans,
                  "oracle_sha256": {p.name: digest(p) for p in oracle.glob("*.json")},
                  "pip_check": "PASSED", "prediction_status": "NOT_RUN"}
    except Exception as exc:
        report = {"status": "FAILED", "project": row, "error": str(exc), "started_at": started,
                  "completed_at": now(), "image": image, "prediction_status": "NOT_RUN"}
    save(manifest_path, report)
    return report


def checkout_source(row, folder, horizon):
    folder = Path(folder)
    if folder.exists() and (folder / ".git").exists():
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=folder, text=True).strip()
        return {"status": "CHECKED_OUT", "commit": commit, "binding": "RELEASE_TAG_NOT_BUILD_ATTESTATION"}
    url = row["repository_url"] + ".git"
    tags = ["v" + row["version"], row["version"], row["name"] + "-" + row["version"]]
    try:
        listing = subprocess.run(["git", "ls-remote", "--tags", url, *["refs/tags/" + t for t in tags]],
                                 capture_output=True, text=True, timeout=30)
        available = {line.split()[1].removeprefix("refs/tags/") for line in listing.stdout.splitlines() if len(line.split()) == 2}
        tag = next((t for t in tags if t in available), None)
        if not tag:
            return {"status": "RELEASE_TAG_UNAVAILABLE", "attempted_tags": tags}
        result = subprocess.run(["git", "clone", "--depth", "1", "--branch", tag, "--", url, str(folder)],
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            return {"status": "CLONE_FAILED", "exit_code": result.returncode}
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=folder, text=True).strip()
        return {"status": "CHECKED_OUT", "tag": tag, "commit": commit, "binding": "RELEASE_TAG_NOT_BUILD_ATTESTATION"}
    except subprocess.TimeoutExpired:
        return {"status": "SOURCE_TIMEOUT"}


def capture_cohort(cohort_file, destination, limit=None, workers=4, source=True):
    cohort = load(cohort_file)
    out = Path(destination).resolve()
    out.mkdir(parents=True, exist_ok=True)
    code = out / "capture_code"
    code.mkdir(exist_ok=True)
    shutil.copyfile(ROOT / "benchmark.py", code / "benchmark.py")
    shutil.copyfile(ROOT / "sbom_recovery/capture_worker.py", code / "capture_worker.py")
    image = load(ROOT / "research/toolchain.json")["image"]
    records = []
    projects = cohort["projects"][:limit] if limit else cohort["projects"]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(capture_project, row, out / row["name"], cohort["config"], image, source): row for row in projects}
        for future in as_completed(futures):
            record = future.result()
            records.append(record)
            status = {"completed": len(records), "total": len(projects), "project": record["project"]["name"], "status": record["status"]}
            print(json.dumps(status), flush=True)
            save(out / "capture_summary.json", {"status": "RUNNING", "records": records,
                    "cohort_sha256": digest(cohort_file), "image": image})
    summary = {"status": "COMPLETE" if all(r["status"] == "COMPLETE" for r in records) else "PARTIAL",
               "cohort_sha256": digest(cohort_file), "selected_projects": len(projects), "image": image,
               "successful_builds": sum(r["status"] == "COMPLETE" for r in records), "records": records}
    save(out / "capture_summary.json", summary)
    return summary
