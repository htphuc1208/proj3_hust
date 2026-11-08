#!/usr/bin/env python3
"""New, development-only reanalysis. No M2.5 predictions or policies are changed."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from research_core import digest, load
from sbom_recovery.contracts import TargetContext
from sbom_recovery.formats import sha
from sbom_recovery.freeze import freeze
from sbom_recovery.storage import save


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", default="runs/m25-cohort-buildable-v4/cohort.json")
    parser.add_argument("--captures", default="research/.work/m25-cohort-captures-v2")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    cohort = load(args.cohort)
    projects = [p for p in cohort["projects"] if p["partition"] == "development"]
    if len(projects) != 20 or len({p["name"] for p in projects}) != 20:
        raise ValueError("Expected exact 20-project development partition")
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    source_sha = freeze(out / "source_bundle")
    shutil.copyfile(__file__, out / "executed-runner.py")
    image = load(ROOT / "research/.work/agent-worker-image/image.json")["image"]
    plan = {"status": "DEVELOPMENT_ONLY", "partition": "development", "projects": [p["name"] for p in projects],
            "runner_sha256": digest(__file__),
            "cohort_sha256": digest(args.cohort), "source_sha256": source_sha, "image": image,
            "input": "Unmodified native Syft installed-target capture",
            "comparison": "Observed graph versus inactive-declaration reconciliation; not additive-control H1 test",
            "time_scope": "Contemporary captured metadata reanalysis; not historical metadata availability",
            "llm_api_calls": 0, "heldout_roots_used": 0, "new_acquisitions": 0}
    save(out / "plan.json", plan)
    records = []
    # All worker predictions are sealed before any independent labels are read.
    for project in projects:
        name = project["name"]
        capture = Path(args.captures).resolve() / name
        case = out / name
        inputs = case / "input"
        inputs.mkdir(parents=True)
        info = load(capture / "capture.json")
        available = info["completed_at"]
        context = TargetContext.model_validate(load(capture / "context.json")).model_copy(update={
            "evidence_cutoff": available,
            "root_purls": [f"pkg:pypi/{project['name']}@{project['version']}"]})
        save(inputs / "context.json", context.model_dump())
        save(inputs / "observation.json", load(capture / "runtime/syft.spdx.json"))
        worker = case / "worker"
        worker.mkdir()
        command = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--memory=1g", "--cpus=1", "--pids-limit=64",
            "--user", f"{os.getuid()}:{os.getgid()}", "--tmpfs", "/tmp:rw,size=64m",
            "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONPATH=/code",
            "-v", f"{out / 'source_bundle'}:/code:ro", "-v", f"{inputs}:/input:ro",
            "-v", f"{capture / 'runtime/target'}:/target:ro", "-v", f"{worker}:/out:rw",
            "--entrypoint", "python", image, "-m", "sbom_recovery.reconciliation",
            "--input", "/input/observation.json", "--context", "/input/context.json",
            "--target", "/target", "--available-at", available, "--out", "/out/result"]
        save(case / "worker-boundary.json", {"command": command, "image": image,
             "oracle_mounted": False, "network": "none", "source_sha256": source_sha,
             "input_sha256": digest(inputs / "observation.json"), "context_sha256": sha(context.model_dump())})
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        save(case / "execution.json", {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        record = {"project": name, "status": "SEALED" if result.returncode == 0 else "WORKER_ERROR",
                  "case": str(case), "capture": str(capture)}
        records.append(record)
        save(out / "progress.json", {"predicted": len(records), "total": len(projects)})
        print(name, record["status"], flush=True)
    # Evaluation occurs outside the worker after the entire dev prediction matrix.
    from sbom_recovery.campaign import score_after_seal
    for record in records:
        if record["status"] != "SEALED":
            continue
        case = Path(record["case"])
        result = case / "worker/result"
        observation = load(case / "input/observation.json")
        prediction_path = result / "reconciled.json"
        if not prediction_path.exists():
            record["status"] = "INVALID_NATIVE_OUTPUT"
            continue
        prediction = load(prediction_path)
        assessment, seal = load(result / "assessment.json"), load(result / "seal.json")
        if (sha(observation) != seal["input_sha256"] or sha(prediction) != seal["prediction_sha256"]
                or sha(assessment) != seal["assessment_sha256"]
                or sha(load(case / "input/context.json")) != seal["context_sha256"]):
            raise ValueError("Prediction/input/context/assessment seal mismatch")
        capture = Path(record["capture"])
        before = score_after_seal(capture, observation, observation)
        after = score_after_seal(capture, observation, prediction)
        save(case / "evaluation.json", {"before": before, "after": after,
             "unknown_label_policy": "Excluded from known negatives; retained explicitly by scorer"})
        removed = set(map(tuple, before["false_positive_edges"])) - set(map(tuple, after["false_positive_edges"]))
        record.update(status="SCORED", before=before["whole_edges"], after=after["whole_edges"],
            retracted=len(assessment["retracted_edges"]), removed_known_fp=len(removed),
            added_fn=after["whole_edges"]["fn"] - before["whole_edges"]["fn"],
            assessment_counts=assessment["counts"], validation=assessment["validation"]["valid"],
            reference_provenance_sha256=digest(capture / "oracle/installed_reference_provenance.json"))
    def mean(field, metric):
        values = [r[field][metric] for r in records if r["status"] == "SCORED" and r[field][metric] is not None]
        return {"eligible_projects": len(values), "mean": statistics.mean(values) if values else None}
    report = {**plan, "status": "COMPLETE_DEVELOPMENT_DIAGNOSTIC" if all(r["status"] == "SCORED" for r in records) else "PARTIAL",
        "generated_at": datetime.now(timezone.utc).isoformat(), "records": records,
        "status_counts": dict(Counter(r["status"] for r in records)),
        "before": {k: mean("before", k) for k in ("precision", "recall", "f1")},
        "after": {k: mean("after", k) for k in ("precision", "recall", "f1")},
        "retracted_edges": sum(r.get("retracted", 0) for r in records),
        "removed_known_fp": sum(r.get("removed_known_fp", 0) for r in records),
        "added_fn": sum(r.get("added_fn", 0) for r in records),
        "security_metrics": "UNMEASURED", "calibration": "UNMEASURED", "agent_advantage": "UNMEASURED"}
    paired = [r for r in records if r["status"] == "SCORED" and r["before"]["tp"] + r["before"]["fn"] > 0]
    report["paired_nonempty_reference"] = {"projects": len(paired),
        "before": {k: statistics.mean(r["before"][k] for r in paired) if paired else None for k in ("precision", "recall", "f1")},
        "after": {k: statistics.mean(r["after"][k] for r in paired) if paired else None for k in ("precision", "recall", "f1")}}
    report["empty_reference_projects"] = sum(r["status"] == "SCORED" and r["before"]["tp"] + r["before"]["fn"] == 0 for r in records)
    save(out / "summary.json", report)
    print(json.dumps({k:report[k] for k in ("status", "before", "after", "retracted_edges", "removed_known_fp", "added_fn")}))


if __name__ == "__main__":
    main()
