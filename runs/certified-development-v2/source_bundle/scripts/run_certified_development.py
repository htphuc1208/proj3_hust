#!/usr/bin/env python3
"""Freeze, isolate, seal and score V2 on old development roots only.

No test/validation partition, registry access or LLM calls are supported here.
The strong semantic control is allowed to tie the proposed method.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sbom_recovery.core.formats import NativeDocument, sha
from sbom_recovery.core.contracts import TargetContext
from sbom_recovery.campaign.freeze import freeze
from sbom_recovery.campaign.targets import metadata_inventory
from sbom_recovery.reconciliation.contracts_v2 import ContextKnowledgeV2, MARKER_NAMES, occurrence_id
from sbom_recovery.reconciliation.certified_evidence import collect_evidence, read_bundle
from sbom_recovery.reconciliation.certified_analysis import load, verify_matrix, score_arm, summarize
from sbom_recovery.reconciliation.certified_worker import METHODS

CONDITIONS = ("full_metadata", "unknown_context", "partial_metadata")


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def stage_case(capture, project, condition, destination):
    destination.mkdir(parents=True, exist_ok=False)
    capture_info = load(capture / "capture.json")
    available = capture_info["completed_at"]
    legacy = TargetContext.model_validate(load(capture / "context.json")).model_copy(update={
        "evidence_cutoff": available, "root_purls": [f"pkg:pypi/{project['name']}@{project['version']}"]})
    document = load(capture / "runtime/syft.spdx.json")
    paths, target_id = metadata_inventory(capture / "runtime/target")
    if target_id != legacy.target_id:
        raise ValueError("Frozen target digest changed")
    scopes = {p.parent.parent.relative_to(capture / "runtime/target").as_posix() for p in paths
              if p.parent.parent.name in {"site-packages", "dist-packages"}}
    if len(scopes) != 1:
        raise ValueError("Expected one explicit installed environment")
    requests = {}
    # The legacy installed-reference contract seeds base declarations for all
    # installed distributions. This is a logical profile, NOT a reconstruction
    # of which extras pip persisted (pip does not persist that history).
    from email.parser import BytesParser
    from packaging.utils import canonicalize_name
    for path in paths:
        if path.parent.parent.name not in {"site-packages", "dist-packages"}:
            continue
        msg = BytesParser().parsebytes(path.read_bytes())
        purl = f"pkg:pypi/{canonicalize_name(msg['Name'])}@{msg['Version']}"
        extras = list(legacy.extras_by_purl.get(purl, []))
        if purl in legacy.root_purls:
            extras += legacy.active_extras
        if extras:
            requests[occurrence_id(target_id, path.relative_to(capture / "runtime/target").as_posix())] = sorted(set(extras))
    context = ContextKnowledgeV2(target_id=target_id, installation_scope=next(iter(scopes)), evidence_cutoff=available,
        marker_values={k: getattr(legacy, k, None) for k in MARKER_NAMES}, root_requests=requests,
        root_requests_complete=True)
    if condition == "unknown_context":
        context = context.model_copy(update={"marker_values": {}, "root_requests": {}, "root_requests_complete": False})
    manifest = collect_evidence(document, context, capture / "runtime/target", available, destination / "evidence")
    withheld = []
    if condition == "partial_metadata":
        # Fixed 50% intervention on source IDs, independent of graph labels and
        # method outcomes. This is controlled withholding, never a natural-loss claim.
        ordered = sorted(manifest.sources, key=lambda s: sha([42, s.source_id]))
        for source in ordered[:len(ordered) // 2]:
            source.acquired = False
            withheld.append(source.source_id)
            (destination / "evidence" / source.path).unlink()
        save(destination / "evidence/manifest.json", manifest.model_dump())
    # Unacquired bytes and hidden legacy context must not remain mounted.
    present = {p.name for p in (destination / "evidence/sources").iterdir()}
    expected = {Path(s.path).name for s in manifest.sources if s.acquired}
    if present != expected:
        raise ValueError("Withheld metadata remains visible to inference")
    save(destination / "observation.json", document)
    save(destination / "context.json", context.model_dump())
    if condition != "unknown_context":
        save(destination / "legacy-context.json", legacy.model_dump())
    job = {"project": project["name"], "partition": "development", "condition": condition,
           "available_at": available, "withheld_sources": withheld, "methods": list(METHODS),
           "input_sha256": sha(document), "context_sha256": sha(context.model_dump()),
           "evidence_sha256": sha(manifest.model_dump()),
           "intervention": "CONTROLLED_EVIDENCE_WITHHOLDING" if condition == "partial_metadata" else
                           "CONTROLLED_CONTEXT_WITHHOLDING" if condition == "unknown_context" else "NONE",
           "context_profile": "ALL_INSTALLED_BASE_DECLARATIONS; explicit extra seeds from captured logical context",
           "reference_labels_read": False}
    save(destination / "job.json", job)
    return job


def execute_case(case, source, image):
    case.mkdir(parents=True, exist_ok=True)
    output = case / "output"
    output.mkdir(exist_ok=False)
    command = ["docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--memory=2g", "--cpus=1", "--pids-limit=128",
        "--tmpfs", "/tmp:rw,size=134217728", "--user", f"{os.getuid()}:{os.getgid()}",
        "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONPATH=/code",
        "-v", f"{source}:/code:ro", "-v", f"{case / 'input'}:/job:ro", "-v", f"{output}:/out:rw",
        "-w", "/code", "--entrypoint", "python", image, "-B", "-m",
        "sbom_recovery.reconciliation.certified_worker", "--job", "/job", "--out", "/out/predictions"]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
    (case / "worker.log").write_text(completed.stdout + completed.stderr)
    save(case / "execution.json", {"command": command, "exit_code": completed.returncode,
        "network": "none", "oracle_mounted": False, "target_mounted": False,
        "hidden_evidence_files_mounted": False})
    if completed.returncode:
        raise RuntimeError(f"Worker failed ({completed.returncode}); see {case / 'worker.log'}")
    verify_matrix(case / "input", output / "predictions")
    return case


def export_review_packet(out, records):
    # Labels are deliberately omitted from review forms; no review is invented.
    tasks = []
    for record in records:
        path = out / record["project"] / record["condition"]
        details = load(path / "output/predictions/certified_v2/details.json")
        for decision in details.get("decisions", []):
            key = sha([record["project"], record["condition"], decision["source_ref"], decision["target_ref"]])
            tasks.append({"task_id": key, "project": record["project"], "condition": record["condition"],
                "decision": decision, "case_path": path.relative_to(out).as_posix(),
                "reviewer": "", "verdict": "", "notes": ""})
    selected = []
    for bucket in ("add", "retract", "abstain"):
        selected += sorted([t for t in tasks if t["decision"]["operation"] == bucket],
                           key=lambda t: sha([42, t["task_id"]]))[:40]
    save(out / "review-packet.json", {"status": "PENDING_SINGLE_AUTHOR_HUMAN_AUDIT", "target": 120,
        "available_selected_tasks": len(selected), "sampling": "up to 40 per add/retract/abstain; hash seed 42",
        "completed_human_reviews": 0, "independent_review": False, "tasks": selected})


def write_report(out, summary):
    rows = []
    for method, values in summary["methods"].items():
        score = values["available_case_f1"]
        rows.append(f"| {method} | {score:.4f} | {values['known_changes']} | {values['incorrect_changes']} | {values['unknown_changes']} |"
                    if score is not None else f"| {method} | undefined | {values['known_changes']} | {values['incorrect_changes']} | {values['unknown_changes']} |")
    text = """# Certified reconciliation V2 — development only

## Question and design

Do scoped completeness checks and executable certificates improve decisions
over strong metadata interpretation? These are old development roots, never a
held-out generalization experiment. Three conditions are separate: full metadata,
controlled context withholding, and controlled 50% metadata withholding (seed 42).
All arms share the same permitted bytes/context. The strong metadata control
shares the semantic trusted base; equality must not be marketed as superiority.

Each case runs in a network-disabled container with only frozen source, staged
evidence and output mounts. Oracle files, full targets, withheld bytes and hidden
legacy context are absent. Every prediction matrix is verified before references
are read. Historical deployment identity and runtime use are unmeasured.

## Results

""" + f"Status: **{summary['status']}**; {summary['projects']} projects, {summary['cases']} paired cases.\n\n" + """| Method | Available-case edge F1 | Known changes | Incorrect changes | Unknown changes |
| --- | ---: | ---: | ---: | ---: |
""" + "\n".join(rows) + f"""

These descriptive means pool conditions and can have different denominators;
they are not valid method-effect contrasts. Per-condition results and paired
project contrasts with common cases are in summary.json. Zero denominators stay
null. Bootstrap/randomization use projects, 10,000 draws and Holm correction.

Certified V2 and the strong semantic control have identical native edge sets in
**{summary['same_graph_as_strong_control_cases']}/{summary['cases']}** cases.
Empirical advantage gate: **{summary['empirical_advantage_gate']}**.

## Interpretation and limitations

Certificates establish derivations under trusted collector/context assertions;
they do not attest executable contents. Existing reference labels score unique
coordinates, not ambiguous physical occurrences. Shared package declarations and
standards libraries remain a common-error threat. Single-environment selected
roots and shared dependencies limit generalization. Controlled withholding is
not evidence of the prevalence of natural evidence loss.

No A* novelty, agent superiority, calibrated probability, exploitability or
security-triage improvement is established. No held-out roots were consumed.
Human audit forms are pending; an LLM review is not counted as a human review.

## Decision

If the strong control ties all cases, do not launch a tuned held-out accuracy
study for this version. Preserve the negative result and investigate whether
independently checkable certificates have a distinct, substantive research
question. This run alone does not establish that contribution.

Replay from frozen source with the recorded image and staged inputs; host paths
in execution.json document this execution, not a portable command. The worker
only requires /code, /job and /out mounts. See research/CERTIFIED_RECONCILIATION.md.
"""
    (out / "REPORT.md").write_text(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", type=Path, default=ROOT / "runs/m25-cohort-buildable-v4/cohort.json")
    parser.add_argument("--captures", type=Path, default=ROOT / "research/.work/m25-cohort-captures-v2")
    parser.add_argument("--references", type=Path, default=ROOT / "runs/m25-installed-reference-v1/manifest.json")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, choices=[1, 2, 3, 4], default=4)
    parser.add_argument("--image", default=None)
    args = parser.parse_args()
    # Test Docker availability before preparing files, so a permission failure
    # can be retried without an ambiguous partial experiment directory.
    subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], check=True, capture_output=True)
    out = args.out.resolve()
    cohort = load(args.cohort)
    reference_records = {r["project"]: r for r in load(args.references)["records"]}
    projects = [p for p in cohort["projects"] if p["partition"] == "development"]
    if len(projects) != 20 or len({p["name"] for p in projects}) != 20:
        raise ValueError("This runner requires the 20 old development roots")
    out.mkdir(parents=True, exist_ok=False)
    source = out / "source_bundle"
    source_sha = freeze(source)
    for relative in ("scripts/run_certified_development.py", "research/CERTIFIED_RECONCILIATION.md",
                     "configs/certified-reconciliation-v2.json"):
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    source_files = {p.relative_to(source).as_posix(): digest(p) for p in source.rglob("*") if p.is_file()}
    save(out / "source-manifest.json", {"files": source_files, "sha256": sha(source_files), "legacy_bundle_sha256": source_sha})
    image = args.image or load(ROOT / "research/.work/agent-worker-image/image.json")["image"]
    plan = {"schema_version": "certified-development-v2", "created_at": datetime.now(timezone.utc).isoformat(),
            "partition": "development", "projects": [p["name"] for p in projects], "methods": list(METHODS),
            "conditions": list(CONDITIONS), "image": image, "source_sha256": sha(source_files),
            "cohort_sha256": digest(args.cohort), "reference_access": "AFTER_ALL_PREDICTIONS_SEALED",
            "reference_manifest_sha256": digest(args.references),
            "llm_api_calls": 0, "heldout_projects_used": 0}
    save(out / "plan.json", plan)
    cases = []
    for project in projects:
        for condition in CONDITIONS:
            case = out / project["name"] / condition
            stage_case(args.captures / project["name"], project, condition, case / "input")
            cases.append(case)
    failures, completed = [], []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(execute_case, case, source, image): case for case in cases}
        for future in as_completed(futures):
            case = futures[future]
            try:
                completed.append(future.result())
            except Exception as exc:
                failures.append({"case": case.relative_to(out).as_posix(), "error": str(exc)[:500]})
            progress = {"finished": len(completed) + len(failures), "total": len(cases), "failed": len(failures)}
            save(out / "progress.json", progress)
            print(json.dumps(progress), flush=True)
    # Mandatory global barrier. No label read occurs above this line.
    verified = {str(case): verify_matrix(case / "input", case / "output/predictions") for case in completed}
    records = []
    for case in sorted(completed):
        project, condition = case.parent.name, case.name
        capture = args.captures / project
        oracle = capture / "oracle"
        provenance = load(oracle / "installed_reference_provenance.json")
        if (digest(oracle / "pip_inspect.json") != provenance["pip_inspect_sha256"]
                or digest(oracle / "install_report.json") != provenance["installation_report_sha256"]):
            raise ValueError("Independent reference input hashes changed")
        reference, gold = load(oracle / "installed_reference.cdx.json"), load(oracle / "installed_reference.json")
        if digest(oracle / "installed_reference.cdx.json") != reference_records[project]["reference_sha256"]:
            raise ValueError("Independent reference differs from the pre-existing frozen manifest")
        unresolved = {n["purl"] for n in gold["nodes"] if any(n["name"] == u.get("parent") for u in gold.get("unresolved", []))}
        observation = load(case / "input/observation.json")
        predictions = verified[str(case)]
        arms = {m: score_arm(observation, p, d, reference, unresolved) for m, (p, d) in predictions.items()}
        record = {"project": project, "condition": condition, "arms": arms,
                  "reference_sha256": digest(oracle / "installed_reference.cdx.json"),
                  "same_graph_as_metadata_control": NativeDocument(predictions["metadata_control"][0]).edges() ==
                                                     NativeDocument(predictions["certified_v2"][0]).edges()}
        records.append(record)
        save(case / "evaluation.json", record)
    summary = summarize(records, failures)
    save(out / "summary.json", summary)
    by_condition = {condition: summarize([r for r in records if r["condition"] == condition], failures)
                    for condition in CONDITIONS}
    save(out / "conditions.json", by_condition)
    export_review_packet(out, records)
    write_report(out, summary)
    print(json.dumps({k: summary[k] for k in ("status", "projects", "cases", "empirical_advantage_gate")}), flush=True)


if __name__ == "__main__":
    main()
