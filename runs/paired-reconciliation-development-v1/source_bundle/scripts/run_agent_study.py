#!/usr/bin/env python3
"""Run the registered study without writing credentials to a job file or child argv.

The primary test has the complete 64-tool matrix. Budget sensitivity is a separate,
declared subset (raw plus 50% masks, seed 11), never pooled with the primary budget.
--background detaches only after reading the key; it remains in process memory.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research_core import digest, load, now
from sbom_recovery.storage import save

METHODS = ["observed", "single_scanner", "sbom_unifier", "unifier_rules",
           "deterministic", "single_agent", "multi_agent"]
DETACHED_CONTROLLERS = []


def stage_specs():
    common = dict(methods=METHODS, conditions=["fixed", "active"], max_turns=64, mask_origin="reference")
    return [
        dict(common, name="calibration", phase="calibration", families=["metadata", "dependency"],
             rates=[.5], seeds=[11], budgets=[64], repetitions=1, expected_cases=80),
        dict(common, name="test/raw", phase="test", families=["raw"],
             rates=[.1, .3, .5, .7], seeds=[11, 23, 42], budgets=[64], repetitions=3, expected_cases=360),
        dict(common, name="test/controlled", phase="test", families=["component", "metadata", "dependency"],
             rates=[.1, .3, .5, .7], seeds=[11, 23, 42], budgets=[64], repetitions=3, expected_cases=12960),
        dict(common, name="test/budget-sensitivity", phase="test", families=["raw", "component", "metadata", "dependency"],
             rates=[.5], seeds=[11], budgets=[16, 256], repetitions=3, expected_cases=2880),
    ]


def status(out):
    result = {"state": load(out / "state.json") if (out / "state.json").exists() else None, "stages": []}
    for stage in stage_specs():
        root = out / stage["name"]
        result["stages"].append({"name": stage["name"], "expected_cases": stage["expected_cases"],
            "progress": load(root / "progress.json") if (root / "progress.json").exists() else None,
            "campaign_status": load(root / "campaign.json").get("status") if (root / "campaign.json").exists() else "NOT_STARTED"})
    return result


def execute(args, key):
    from sbom_recovery.__main__ import benchmark
    from sbom_recovery.calibration import extract_decisions, fit_project_conformal
    from sbom_recovery.campaign import summarize
    from sbom_recovery.freeze import freeze
    from sbom_recovery.reporting import report
    from sbom_recovery.security import score_campaign_security
    from sbom_recovery.selection import select_model

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    # Prevent two controllers from modifying the same campaign. The descriptor is
    # inherited by a detached controller and held until all workers finish.
    lock = (out / "controller.lock").open("a+")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    plan = {"schema_version": "agent-study-v2", "runner_sha256": digest(__file__),
            "cohort": args.cohort, "cohort_sha256": digest(args.cohort), "captures": args.captures,
            "development_runs": args.development_runs, "snapshot": args.snapshot,
            "snapshot_sha256": digest(args.snapshot), "workers": args.workers,
            "source_sha256": freeze(out / "source_bundle"), "stages": stage_specs(),
            "total_token_cap": None, "prediction_source": "immutable source_bundle",
            "controlled_input": "Independent installed reference; trusted masking before blind prediction",
            "budget_sensitivity": "raw and 50% masks; seed 11; separate from primary 64-tool matrix"}
    if (out / "plan.json").exists() and load(out / "plan.json") != plan:
        raise ValueError("Study plan/source changed; use a fresh output directory")
    save(out / "plan.json", plan)
    state = {"status": "RUNNING", "pid": os.getpid(), "started_or_resumed_at": now(),
             "completed_stages": [], "plan_sha256": digest(out / "plan.json")}
    save(out / "state.json", state)
    selection_file = out / "model-selection.json"
    calibration_file = out / "calibration/conformal.json"
    try:
        while True:
            pending = []
            for name in args.development_runs:
                path = Path(name) / "campaign.json"
                if not path.exists():
                    pending.append(name)
                    continue
                campaign = load(path)
                if campaign.get("status") in {"COMPLETE", "PARTIAL"}:
                    continue
                if campaign.get("status") in {"FAILED", "INTERRUPTED"}:
                    raise ValueError("Development controller stopped: " + name)
                pid = campaign.get("controller_pid")
                if pid:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        raise ValueError("Development controller is no longer running: " + name)
                pending.append(name)
            if not pending:
                break
            state.update(status="WAITING_DEVELOPMENT", pending_development=pending, updated_at=now())
            save(out / "state.json", state)
            time.sleep(15)
        state.update(status="RUNNING", pending_development=[])
        if not selection_file.exists():
            select_model(args.development_runs, args.cohort, selection_file, args.captures)
        selection = load(selection_file)
        if selection.get("status") != "FROZEN" or selection["cohort_sha256"] != digest(args.cohort):
            raise ValueError("Frozen model selection belongs to another cohort")
        for spec in stage_specs():
            state.update(current_stage=spec["name"], updated_at=now())
            save(out / "state.json", state)
            root = out / spec["name"]
            options = {k: v for k, v in spec.items() if k not in {"name", "expected_cases"}}
            options.update(command="benchmark", cohort=args.cohort, captures=args.captures,
                out=str(root), workers=args.workers, projects=None, model=None,
                selection=str(selection_file), single_scanner=None,
                calibration=str(calibration_file) if spec["phase"] == "test" else None, ask_key=False)
            result = benchmark(argparse.Namespace(**options), secret=key)
            progress = load(root / "progress.json")
            if progress["completed_cases"] != spec["expected_cases"]:
                raise ValueError("Completed case count differs from the frozen study matrix")
            if spec["phase"] == "calibration":
                decisions = root / "decisions.json"
                extract_decisions(root, args.captures, decisions)
                extract_decisions(root, args.captures, root / "all-proposals-decisions.json", eligible_only=False)
                fitted = fit_project_conformal(load(decisions))
                if calibration_file.exists() and load(calibration_file) != fitted:
                    raise ValueError("Calibration changed across resume")
                save(calibration_file, fitted)
            else:
                score_campaign_security(root, args.captures, args.snapshot)
                summarize(out / "test")
                report(out / "test", out / "report")
            state["completed_stages"].append({"name": spec["name"], "status": result["status"],
                "completed_at": now(), "campaign_sha256": digest(root / "campaign.json")})
            save(out / "state.json", state)
        state.update(status="EXECUTED_WITH_EXPLICIT_FAILURES" if any(
            s["status"] != "COMPLETE" for s in state["completed_stages"]) else "COMPLETE",
            current_stage=None, completed_at=now())
        save(out / "state.json", state)
    except BaseException as exc:
        state.update(status="INTERRUPTED" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else "FAILED",
                     error_type=type(exc).__name__, error=str(exc), updated_at=now())
        save(out / "state.json", state)
        raise
    finally:
        lock.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cohort", default="runs/m25-cohort-buildable-v4/cohort.json")
    p.add_argument("--captures", default="research/.work/m25-cohort-captures-v2")
    p.add_argument("--development-runs", nargs="+", default=["runs/m25-development-qwen36-v2", "runs/m25-development-qwen35-v2"])
    p.add_argument("--snapshot", default="runs/m25-osv-snapshot-v1/snapshot.json")
    p.add_argument("--out", required=True)
    p.add_argument("--workers", type=int, choices=[2, 3, 4], default=4)
    p.add_argument("--ask-key", action="store_true")
    p.add_argument("--background", action="store_true")
    p.add_argument("--status", action="store_true")
    p.add_argument("--describe", action="store_true")
    p.add_argument("--frozen-worker", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--key-fd", type=int, help=argparse.SUPPRESS)
    args = p.parse_args()
    os.chdir(ROOT)
    out = Path(args.out)
    if args.status or args.describe:
        print(json.dumps(status(out) if args.status else {"stages": stage_specs()}, indent=2))
        return
    if args.frozen_worker:
        if args.key_fd is None:
            raise ValueError("The frozen controller requires an inherited credential pipe")
        try:
            key = os.read(args.key_fd, 4096).decode().strip()
        finally:
            os.close(args.key_fd)
        if not key:
            raise ValueError("The credential pipe was empty")
        execute(args, key)
        return
    from sbom_recovery.llm import read_key
    key = read_key(args.ask_key)
    if not key:
        raise ValueError("A gateway credential is required")
    result, process = launch_frozen(args, key)
    if args.background:
        DETACHED_CONTROLLERS.append(process)
    print(json.dumps(result), flush=True)


def launch_frozen(args, key):
    """Use a fresh interpreter so later working-tree edits cannot alter a study."""
    from sbom_recovery.freeze import freeze
    out = Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=True)
    bundle = out / "source_bundle"
    source_sha = freeze(bundle)
    work = bundle / "research/.work"
    if not work.exists():
        work.symlink_to((ROOT / "research/.work").resolve(), target_is_directory=True)
    if work.resolve() != (ROOT / "research/.work").resolve():
        raise ValueError("Frozen source has unexpected runtime resources")
    read_fd, write_fd = os.pipe()
    command = [sys.executable, "-B", str(bundle / "scripts/run_agent_study.py"),
        "--cohort", str(Path(args.cohort).resolve()), "--captures", str(Path(args.captures).resolve()),
        "--snapshot", str(Path(args.snapshot).resolve()), "--out", str(out), "--workers", str(args.workers),
        "--development-runs", *[str(Path(p).resolve()) for p in args.development_runs],
        "--frozen-worker", "--key-fd", str(read_fd)]
    # The one-use pipe is closed before any prediction process is created.
    # Nothing stores the key in source, argv, an environment variable or a log.
    log = os.open(out / "controller.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600) if args.background else None
    try:
        process = subprocess.Popen(command, pass_fds=(read_fd,), start_new_session=args.background,
            stdin=subprocess.DEVNULL if args.background else None, stdout=log, stderr=subprocess.STDOUT if args.background else None,
            env={k: v for k, v in os.environ.items() if k != "NETMIND_API_KEY"})
    finally:
        os.close(read_fd)
        if log is not None:
            os.close(log)
    try:
        os.write(write_fd, key.encode())
    finally:
        os.close(write_fd)
    result = {"controller_pid": process.pid, "source_sha256": source_sha, "log": str(out / "controller.log"),
              "status_command": f"{sys.executable} -B scripts/run_agent_study.py --out {out} --status"}
    if not args.background:
        result["exit_code"] = process.wait()
    return result, process


if __name__ == "__main__":
    main()
