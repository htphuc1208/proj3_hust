#!/usr/bin/env python3
"""Correct the installed scanner mode in a new capture tree; retain prior bytes."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research_core import digest, load, now
from sbom_recovery.storage import save
from sbom_recovery.targets import metadata_inventory


def copy_frozen(source, destination):
    # Mutable Git bookkeeping and reports have their own bytes; target payloads
    # are frozen shared hard links. The new scan is written to a fresh inode.
    if "/.git/" in str(source) or Path(source).suffix in {".log", ".json"}:
        return shutil.copy2(source, destination)
    os.link(source, destination)
    return destination


def correct(previous, destination):
    previous, destination = Path(previous).resolve(), Path(destination).resolve()
    proof = destination / "scanner-correction.json"
    if proof.exists():
        prior = load(proof)
        if prior["status"] == "COMPLETE" and prior["previous_capture_sha256"] == digest(previous / "capture.json") and prior["new_output_sha256"] == digest(destination / "runtime/trivy.spdx.json"):
            return prior
        raise ValueError("Incomplete or changed correction; preserve it and choose a new destination")
    if destination.exists():
        if digest(destination / "capture.json") != digest(previous / "capture.json") or digest(destination / "runtime/trivy.spdx.json") != digest(previous / "runtime/trivy.spdx.json"):
            raise ValueError("Unfinished correction no longer matches the preserved inputs")
        failed_log = destination / "trivy-rootfs.log"
        if failed_log.exists():
            shutil.copyfile(failed_log, failed_log.with_name("trivy-rootfs.failed-" + digest(failed_log)[:16] + ".log"))
    else:
        shutil.copytree(previous, destination, symlinks=True, copy_function=copy_frozen)
    original = destination / "runtime/trivy.spdx.json"
    shutil.copyfile(original, destination / "runtime/trivy-fs.legacy.spdx.json")
    target = destination / "runtime/target"
    _, target_digest = metadata_inventory(target)
    if target_digest != load(destination / "context.json")["target_id"]:
        raise ValueError("Target payload changed before scanner correction")
    pending = destination / "runtime/trivy-rootfs.pending.json"
    binary = ROOT / "research/.work/trivy"
    command = [str(binary), "rootfs", "--offline-scan", "--skip-db-update", "--skip-java-db-update",
               "--disable-telemetry", "--skip-version-check", "--parallel", "2", "--format", "spdx-json",
               "--output", str(pending), str(target)]
    start = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True, timeout=300)
    (destination / "trivy-rootfs.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError("Corrected rootfs scan failed: " + previous.name)
    load(pending)
    os.replace(pending, original)
    capture = deepcopy(load(previous / "capture.json"))
    capture["scanners"]["trivy"] = {"command": command, "exit_code": 0, "seconds": time.monotonic() - start,
        "binary_sha256": digest(binary), "scope": "installed filesystem; rootfs analyzer mode"}
    capture["scanner_correction"] = {"reason": "fs mode targets project manifests; installed wheel metadata requires rootfs mode",
        "previous_capture": str(previous), "previous_capture_sha256": digest(previous / "capture.json"),
        "corrected_at": now(), "target_bytes_changed": False, "labels_changed": False}
    save(destination / "capture.json", capture)
    correction = {"status": "COMPLETE", "project": previous.name, "target_id": target_digest,
        **capture["scanner_correction"], "new_output_sha256": digest(original),
        "legacy_output_sha256": digest(destination / "runtime/trivy-fs.legacy.spdx.json"),
        "runner_sha256": digest(__file__)}
    save(proof, correction)
    return correction


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--previous", required=True); p.add_argument("--out", required=True)
    p.add_argument("--manifest", required=True); p.add_argument("--cohort", required=True)
    p.add_argument("--workers", type=int, default=4)
    args = p.parse_args()
    records = []
    projects = load(args.cohort)["projects"]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(correct, Path(args.previous) / project["name"], Path(args.out) / project["name"]) for project in projects]
        for future in as_completed(futures):
            try:
                row = future.result()
            except Exception as exc:
                row = {"status": "FAILED", "error_type": type(exc).__name__, "error": str(exc)}
            records.append(row)
            save(args.manifest, {"status": "RUNNING", "records": records, "completed": len(records), "total": len(projects)})
            print({"project": row.get("project"), "status": row["status"], "completed": len(records)}, flush=True)
    save(args.manifest, {"status": "COMPLETE" if all(r["status"]=="COMPLETE" for r in records) else "PARTIAL", "records": records, "completed": len(records), "total": len(projects),
        "cohort_sha256": digest(args.cohort), "runner_sha256": digest(__file__), "completed_at": now(),
        "official_source": "https://www.trivy.dev/docs/latest/guide/coverage/language/python/"})


if __name__ == "__main__":
    main()
