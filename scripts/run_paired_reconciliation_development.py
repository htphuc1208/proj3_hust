#!/usr/bin/env python3
"""Freeze and run the three-arm full-metadata comparison on 20 old development roots."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from research_core import digest, load
from sbom_recovery.contracts import TargetContext
from sbom_recovery.formats import sha
from sbom_recovery.freeze import freeze
from sbom_recovery.reconciliation_comparison import METHODS, summarize, verify_predictions
from sbom_recovery.storage import save
from sbom_recovery.targets import metadata_inventory


def evaluate_case(case, capture, reference_record):
    # This function is called only after the whole prediction matrix is sealed.
    from sbom_recovery.campaign import score_after_seal
    from sbom_recovery.metrics import graph_facts
    from sbom_recovery.paired_reconciliation import native_changes
    from sbom_recovery.reconciliation_comparison import stage_changes
    observation, context = load(case / "input/observation.json"), load(case / "input/context.json")
    predictions, details = verify_predictions(case / "worker/result", observation, context)
    oracle = capture / "oracle"
    reference = load(oracle / "installed_reference.cdx.json")
    if digest(oracle / "installed_reference.cdx.json") != reference_record["reference_sha256"]:
        raise ValueError("Independent reference changed from frozen reference manifest")
    provenance = load(oracle / "installed_reference_provenance.json")
    if (digest(oracle / "pip_inspect.json") != provenance["pip_inspect_sha256"]
            or digest(oracle / "install_report.json") != provenance["installation_report_sha256"]):
        raise ValueError("Independent reference input provenance changed")
    gold = load(oracle / "installed_reference.json")
    unresolved = {n["purl"] for n in gold["nodes"] if any(n["name"] == u.get("parent") for u in gold.get("unresolved", []))}
    record = {"project": capture.name, "status": "SCORED", "reference_edges": len(graph_facts(reference)[1]),
              "arms": {}, "reference_hashes": {p.name: digest(p) for p in [
                  oracle / "installed_reference.cdx.json", oracle / "installed_reference.json",
                  oracle / "installed_field_labels.json", oracle / "installed_reference_provenance.json"]}}
    for method in METHODS:
        evaluation = score_after_seal(capture, observation, predictions[method])
        save(case / method / "evaluation.json", evaluation)
        detail = details[method]
        record["arms"][method] = {"status": detail["status"], "native_valid": detail["validation"]["valid"],
            "whole_edges": evaluation["whole_edges"], "new_edges": evaluation["new_edges"],
            "whole_nodes": evaluation["whole_nodes"], "new_nodes": evaluation["new_nodes"],
            "whole_metadata": evaluation["whole_metadata"], "new_metadata": evaluation["new_metadata"],
            "unknown_label_edges": evaluation["unknown_label_edge_count"],
            "failure_taxonomy_counts": evaluation["failure_taxonomy_counts"],
            "duration_seconds": detail["duration_seconds"],
            "native_changes": detail["native_changes_from_observation"],
            "assessment_counts": detail.get("assessment", {}).get("counts", {}),
            "accepted_operations": dict(Counter(
                row["proposal"]["operation"] for row in detail.get("verified", {}).get("accepted", [])))}
    record["arms"]["additive_reconciliation"]["native_changes_from_additive"] = native_changes(
        predictions["additive"], predictions["additive_reconciliation"])
    record["stage_changes"] = {
        "additive": stage_changes(observation, predictions["additive"], reference, unresolved),
        "reconciliation": stage_changes(predictions["additive"], predictions["additive_reconciliation"], reference, unresolved)}
    # Attach each retraction's conditional evidence without promoting UNKNOWN to a negative.
    native_map = {tuple(row["edge"]): row["label"] for row in record["stage_changes"]["reconciliation"]["removed"]}
    save(case / "stage-attribution.json", {"changes": record["stage_changes"],
         "retraction_fact_labels": [{"edge": list(edge), "label": label} for edge, label in native_map.items()],
         "causal_taxonomy": "Residual FP/FN causes remain UNRESOLVED unless independently supported; no scanner-internal cause inferred"})
    return record


def write_report(out, summary):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    panel = summary["paired_nonempty_reference"]["metrics"]
    labels = {"observed": "Observed", "additive": "Additive", "additive_reconciliation": "Additive + reconciliation"}
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5), constrained_layout=True)
    positions = np.arange(3)
    for i, method in enumerate(METHODS):
        axes[0].bar(positions + (i - 1) * .25, [panel[k]["means"][method] if panel[k]["means"][method] is not None else np.nan for k in ("precision", "recall", "f1")],
                    width=.25, label=labels[method])
    axes[0].set_xticks(positions, [f"{k}\nn={panel[k]['eligible_projects']}" for k in ("precision", "recall", "f1")])
    axes[0].set_ylim(0, 1.12)
    axes[0].set_ylabel("Project-macro score, common eligible projects")
    axes[0].legend(fontsize=8)
    for i, kind in enumerate(("fp", "fn")):
        axes[1].bar(positions + (i - .5) * .35, [summary["totals"][m]["edge_counts"][kind] for m in METHODS],
                    width=.35, label=kind.upper())
    axes[1].set_xticks(positions, ["Observed", "Additive", "Additive +\nreconciliation"])
    axes[1].set_ylabel("Project/edge occurrences across all 20 projects")
    axes[1].legend()
    fig.suptitle("Development only · full captured metadata · no LLM calls")
    for extension in ("svg", "pdf"):
        fig.savefig(out / ("comparison." + extension))
    plt.close(fig)
    rows = []
    for method in METHODS:
        values = [panel[k]["means"][method] for k in ("precision", "recall", "f1")]
        rendered = [f"{v:.4f}" if v is not None else "undefined" for v in values]
        counts = summary["totals"][method]["edge_counts"]
        rows.append(f"| {labels[method]} | " + " | ".join(rendered) + f" | {counts['fp']} | {counts['fn']} |")
    stage = summary["stage_changes"]
    text = f"""# Three-arm SBOM development comparison

## Context & Problem Formulation

This run compares the unmodified Syft observation, the existing deterministic repair policy, and that exact repair prediction followed by inactive-declaration reconciliation. All 20 roots are old development projects. Outputs are candidate declared graphs conditioned on the captured target/context; they do not attest deployed artifacts or executed code.

## Theoretical Background & Sourcing

[PyPA, Dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/) supplies marker/extras/version semantics. [SPDX 2.3.1, Relationships](https://spdx.github.io/spdx-spec/v2.3.1/relationships-between-SPDX-elements/) defines direct/inverse dependencies. The policies are local engineering baselines, with no novelty or generalization claim. The original source and installed graph scopes remain distinct.

## Hypothesis & Experimental Design

The descriptive questions are what the existing additive policy restores and whether subsequent conservative reconciliation reduces known FP edges without removing known true edges. Methods have the same full, digest-bound top-level METADATA permissions, observation and context. No scanner peers, registries, oracle seeds or model calls are used. Existing additive field/component behavior and explicit-declaration conflict handling remain unchanged. Its identity changes are counted separately from native edge additions.

One network-disabled Docker worker per project shares one snapshot across all three arms. All 60 predictions are sealed and integrity checked before opening independent labels. Labels are bound to the frozen installed-reference manifest and original pip-inspect/install-report hashes. Contemporary capture-completion availability is used; historical METADATA availability is not asserted. Native invalidity and policy failures remain visible alongside extracted-fact scores. Policy time excludes shared preparation and final export checks; combined time includes the reused additive computation. Container elapsed time is recorded separately and is not a performance benchmark.

## Empirical Evidence & Downstream Metrics

Status: **{summary['status']}**, {summary['scored_projects']}/20 scored projects. Precision, recall and F1 below use the same per-metric eligible projects across all arms, within the {summary['paired_nonempty_reference']['population_projects']} projects whose reference contains edges. FP/FN counts use all scored projects, including the {summary['empty_reference_projects']} empty-reference projects.

| Method | Precision | Recall | F1 | FP, all projects | FN, all projects |
| --- | ---: | ---: | ---: | ---: | ---: |
""" + "\n".join(rows) + f"""

Metric denominators: { {k: panel[k]['eligible_projects'] for k in panel} }. Undefined scores remain undefined, never filled with a perfect score. Available-case means are retained separately in summary.json and must not be subtracted across different populations.

Additive stage graph-fact additions: {stage['additive']['added']}; graph-fact removals: {stage['additive']['removed']}. Actual native edge additions: {summary['native_edge_additions']}; changed identity references: {summary['identity_changed_refs']}. Graph-fact changes from identity correction are not relabeled as native edge additions.

Reconciliation graph-fact removals: {stage['reconciliation']['removed']}; additions: {stage['reconciliation']['added']}. Actual native edge retractions: {summary['native_edge_retractions']}. KNOWN_TRUE removals are incorrect retractions; UNKNOWN labels cannot receive FP-removal credit. Per-project evaluations and stage-attribution.json retain each edge and label. Unknown assessments: {summary['assessment_counts'].get('UNKNOWN', 0)}. summary.json records the single operating point's retraction coverage/selective risk and explicit undefined denominators; there is no calibrated probability or threshold curve.

VRR, VEX triage delta, false-assurance reduction, static call paths and exploitability are **UNMEASURED**. No path means UNKNOWN. No inferential significance or agent-superiority claim is made from these development measurements. Standalone figures: [SVG](comparison.svg), [PDF](comparison.pdf).

## Failure Taxonomy & Threats to Validity

Known graph errors retain the existing A–E/UNRESOLVED accounting; errors without causal evidence remain UNRESOLVED. Contradiction evidence concerns inactive declarations, not an identified internal scanner bug. Construct validity stops at package declarations and PURL-pair graph facts. Shared standards libraries/underlying metadata, coordinate-conditioned identity, information-rich evidence and reuse of inspected development roots limit internal validity. Twenty selected Python roots, one environment, shared dependencies and empty graphs limit external validity. These are not 60 independent projects. Operational and native-validation statuses appear in summary.json.

## Actionable Next Steps

Preserve these results and the frozen M2.5 study. Diagnose discrepancies on development only. Implement and freeze the budgeted acquisition controls separately before testing LLM source selection at budgets 4/16. Freeze untouched roots and calibration/analysis before a new held-out evaluation. Independent human/discovery review and scanner-to-artifact scope correctness still gate the 30-case corpus expansion.

Replay with a fresh output path: `.venv/bin/python -B scripts/run_paired_reconciliation_development.py --out runs/paired-reconciliation-new`. Local captured targets, references and the pinned Docker image are required; hashes are not a complete portable replay bundle.
"""
    (out / "REPORT.md").write_text(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", default=str(ROOT / "runs/m25-cohort-buildable-v4/cohort.json"))
    parser.add_argument("--captures", default=str(ROOT / "research/.work/m25-cohort-captures-v2"))
    parser.add_argument("--references", default=str(ROOT / "runs/m25-installed-reference-v1/manifest.json"))
    parser.add_argument("--image")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    cohort = load(args.cohort)
    projects = [p for p in cohort["projects"] if p["partition"] == "development"]
    if len(projects) != 20 or len({p["name"] for p in projects}) != 20:
        raise ValueError("Expected all 20 distinct development projects")
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    source_sha = freeze(out / "source_bundle")
    shutil.copyfile(__file__, out / "executed-runner.py")
    image = args.image or load(ROOT / "research/.work/agent-worker-image/image.json")["image"]
    plan = {"schema_version": "paired-reconciliation-development-v1", "partition": "development",
        "methods": list(METHODS), "projects": [p["name"] for p in projects], "cases": [],
        "source_sha256": source_sha, "runner_sha256": digest(__file__), "image": image,
        "cohort_sha256": digest(args.cohort), "reference_manifest_sha256": digest(args.references),
        "time_scope": "Contemporary captured metadata reanalysis", "condition": "full_metadata",
        "llm_api_calls": 0, "heldout_roots_used": 0, "started_at": datetime.now(timezone.utc).isoformat()}
    for project in projects:
        capture = Path(args.captures).resolve() / project["name"]
        case = out / project["name"]
        info = load(capture / "capture.json")
        available = info["completed_at"]
        context = TargetContext.model_validate(load(capture / "context.json")).model_copy(update={
            "evidence_cutoff": available, "root_purls": [f"pkg:pypi/{project['name']}@{project['version']}"]})
        if metadata_inventory(capture / "runtime/target")[1] != context.target_id:
            raise ValueError("Target changed before the frozen plan")
        inputs = case / "input"
        inputs.mkdir(parents=True)
        save(inputs / "context.json", context.model_dump())
        save(inputs / "observation.json", load(capture / "runtime/syft.spdx.json"))
        plan["cases"].append({"project": project["name"], "capture": str(capture), "available_at": available,
            "input_sha256": sha(load(inputs / "observation.json")), "context_sha256": sha(context.model_dump()),
            "target_id": context.target_id})
    save(out / "plan.json", plan)
    failures = []
    for index, spec in enumerate(plan["cases"]):
        case, capture = out / spec["project"], Path(spec["capture"])
        worker = case / "worker"
        worker.mkdir()
        name = "sbom-paired-" + uuid.uuid4().hex
        command = ["docker", "run", "--rm", "--name", name, "--network", "none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--memory=1g", "--cpus=1", "--pids-limit=64",
            "--user", f"{os.getuid()}:{os.getgid()}", "--tmpfs", "/tmp:rw,size=64m",
            "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONPATH=/code",
            "-v", f"{out / 'source_bundle'}:/code:ro", "-v", f"{case / 'input'}:/input:ro",
            "-v", f"{capture / 'runtime/target'}:/target:ro", "-v", f"{worker}:/out:rw",
            "--entrypoint", "python", image, "-m", "sbom_recovery.paired_reconciliation",
            "--input", "/input/observation.json", "--context", "/input/context.json", "--target", "/target",
            "--available-at", spec["available_at"], "--out", "/out/result"]
        save(case / "worker-boundary.json", {"command": command, "network": "none", "oracle_mounted": False,
             "input_sha256": spec["input_sha256"], "context_sha256": spec["context_sha256"], "image": image,
             "source_sha256": source_sha})
        start = time.perf_counter()
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=120)
            execution = {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=20)
            execution = {"returncode": None, "status": "WORKER_TIMEOUT"}
        execution["container_elapsed_seconds"] = time.perf_counter() - start
        save(case / "execution.json", execution)
        if execution["returncode"] != 0:
            failures.append({"project": spec["project"], "status": "WORKER_ERROR"})
        print(spec["project"], "SEALED" if execution["returncode"] == 0 else "WORKER_ERROR", flush=True)
        save(out / "progress.json", {"predicted_cases": index + 1, "total_cases": 20, "failures": failures})
    # Check the complete predicted matrix before reading any reference labels.
    for spec in plan["cases"]:
        case = out / spec["project"]
        if any(f["project"] == spec["project"] for f in failures):
            continue
        observation, context = load(case / "input/observation.json"), load(case / "input/context.json")
        if sha(observation) != spec["input_sha256"] or sha(context) != spec["context_sha256"]:
            raise ValueError("Frozen input/context changed")
        verify_predictions(case / "worker/result", observation, context)
    save(out / "prediction-matrix-sealed.json", {"cases": 20, "failures": failures,
         "sealed_at": datetime.now(timezone.utc).isoformat(), "plan_sha256": sha(plan),
         "predictions": {p.relative_to(out).as_posix(): digest(p) for p in out.glob("*/worker/result/*/prediction.json")}})
    if digest(args.references) != plan["reference_manifest_sha256"]:
        raise ValueError("Frozen reference manifest changed")
    reference_records = {r["project"]: r for r in load(args.references)["records"]}
    records = []
    for spec in plan["cases"]:
        if any(f["project"] == spec["project"] for f in failures):
            records.append({"project": spec["project"], "status": "WORKER_ERROR", "output_unavailable": True})
        else:
            records.append(evaluate_case(out / spec["project"], Path(spec["capture"]), reference_records[spec["project"]]))
    summary = {**summarize(records), "status": "COMPLETE_DEVELOPMENT_COMPARISON" if not failures else "PARTIAL",
        "planned_projects": 20, "records": records, "failed_projects": failures,
        "operational_failure_policy": "Retain every failure; absent worker outputs have no graph score and completion is reported separately",
        "llm_api_calls": 0, "new_acquisitions": 0, "heldout_roots_used": 0,
        "downstream_metrics": "UNMEASURED", "plan_sha256": sha(plan)}
    save(out / "summary.json", summary)
    write_report(out, summary)
    save(out / "artifact-hashes.json", {str(p.relative_to(out)): digest(p) for p in sorted(out.rglob("*"))
         if p.is_file() and p.name != "artifact-hashes.json"})
    print(json.dumps({k: summary[k] for k in ("status", "stage_changes", "paired_nonempty_reference", "native_edge_additions", "native_edge_retractions")}))


if __name__ == "__main__":
    main()
