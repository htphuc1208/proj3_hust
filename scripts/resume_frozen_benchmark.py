#!/usr/bin/env python3
"""Resume an interrupted benchmark with its original immutable source bundle.

Only unfinished episodes are archived. Sealed predictions and their original
API accounting remain untouched. Credentials stay in controller memory.
"""
from __future__ import annotations

import argparse
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import signal
import sys

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def resume(run, key):
    os.chdir(ROOT)
    run = Path(run)
    bundle = (run / "source_bundle").resolve()
    frozen = json.loads((bundle / "source_manifest.json").read_text())
    for name, expected in frozen["files"].items():
        if digest(bundle / name) != expected:
            raise ValueError("Frozen source mismatch: " + name)
    work = bundle / "research/.work"
    if not work.exists():
        work.symlink_to(ROOT / "research/.work", target_is_directory=True)
    if work.resolve() != (ROOT / "research/.work").resolve():
        raise ValueError("Frozen runtime resources point to another workspace")
    # container_runner is an import-time dependency of the old capture CLI. It
    # is not called by this benchmark; journal the supplemental import bytes.
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(bundle))
    from sbom_recovery.__main__ import benchmark
    from sbom_recovery.llm import Gateway
    from sbom_recovery.storage import save
    from research_core import now

    if Path(sys.modules["sbom_recovery"].__file__).resolve().parent != bundle / "sbom_recovery":
        raise ValueError("Prediction did not import the frozen package")
    lock = (run / "resume-controller.lock").open("a+")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    audit = ROOT / "runs/m25-resume-audit-v1" / run.name / now().replace(":", "-")
    audit.mkdir(parents=True)
    original = json.loads((run / "campaign.json").read_text())
    save(audit / "previous_campaign.json", original)
    incomplete = []
    for arm in sorted(run.rglob("turn-000.json")):
        if (arm.parent / "seal.json").exists():
            continue
        destination = audit / "unfinished-episodes" / arm.parent.relative_to(run)
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.rename(arm.parent, destination)
        incomplete.append(str(destination))
    save(audit / "resume.json", {"run": str(run), "frozen_source_sha256": frozen["sha256"],
        "resumed_at": now(), "archived_episodes": incomplete, "credential_written": False,
        "supplemental_import": {"container_runner.py": digest(ROOT / "container_runner.py")},
        "interrupted_usage": "Prior per-turn usage is preserved; in-flight responses may be unreported"})
    options = {k: v for k, v in original["settings"].items()
               if k not in {"cohort_sha256", "protocol_sha256", "source_sha256"}}
    options["ask_key"] = False
    probe = Gateway(key)
    try:
        ids = {r["id"] for r in probe.models().get("data", [])}
        save(audit / "gateway-check.json", {"model": options["model"], "listed": options["model"] in ids,
            "checked_at": now(), "provider_revision": "UNKNOWN"})
        if options["model"] not in ids:
            raise ValueError("The frozen model is no longer listed by the gateway")
    finally:
        probe.close()
    try:
        result = benchmark(argparse.Namespace(**options), secret=key)
        save(audit / "completion.json", {"status": result["status"], "completed_at": now()})
    finally:
        lock.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", required=True)
    p.add_argument("--background", action="store_true")
    args = p.parse_args()
    key = getpass.getpass("Gateway key: ")
    if args.background:
        sys.stdout.flush(); sys.stderr.flush()
        pid = os.fork()
        if pid:
            print(json.dumps({"pid": pid, "run": args.run, "log": str(Path(args.run) / "resume-controller.log")}))
            return
        os.setsid(); signal.signal(signal.SIGHUP, signal.SIG_IGN)
        fd = os.open(ROOT / args.run / "resume-controller.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.dup2(fd, 1); os.dup2(fd, 2); os.close(fd)
        fd = os.open(os.devnull, os.O_RDONLY); os.dup2(fd, 0); os.close(fd)
        try:
            resume(args.run, key)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    resume(args.run, key)


if __name__ == "__main__":
    main()
