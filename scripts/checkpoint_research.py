#!/usr/bin/env python3
"""Read-only state reconciliation and hash checkpoint, without starting campaigns."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research_core import digest, load
from sbom_recovery.formats import sha
from sbom_recovery.gold_review import check_reviews
from sbom_recovery.storage import save


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if (out / "checkpoint.json").exists():
        raise FileExistsError(out / "checkpoint.json")
    reviews = ROOT / "runs/gold-pilot-v3/reviews"
    claims = check_reviews(reviews / "packet.json", [reviews / f"review-{s}.json" for s in "AB"], out / "claim-review")
    discovery = check_reviews(reviews / "discovery-packet.json", [reviews / f"discovery-{s}.json" for s in "AB"], out / "discovery-review")
    study = ROOT / "runs/m25-agent-study-v2"
    state = load(study / "state.json")
    artifacts = [study / "state.json", study / "plan.json", study / "test/raw/progress.json",
                 study / "test/controlled/progress.json",
                 ROOT / "runs/m25-raw-final-audit-v1.job.json",
                 ROOT / "runs/gold-pilot-v3/manifest.json", ROOT / "runs/gold-pilot-v3/verification.json",
                 ROOT / "runs/materialized-scope-v3/manifest.json",
                 ROOT / "runs/materialized-scope-v3-sandbox-audit/validation/verification.json",
                 ROOT / "configs/pilot30_selection_protocol.json"]
    for directory in ("reconciliation-development-v1", "reconciliation-development-v2", "instance-evidence-v1"):
        artifacts.extend(p for p in (ROOT / "runs" / directory).rglob("*") if p.is_file())
    artifact_hashes = {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(artifacts))}
    save(out / "artifact-hashes.json", artifact_hashes)
    sources = list(ROOT.glob("*.py")) + list(ROOT.glob("requirements*.txt")) + [ROOT / "README.md"]
    for directory, extensions in (("sbom_recovery", {".py"}), ("scripts", {".py"}), ("tests", {".py"}),
                                  ("configs", {".json"}), ("research", {".md"}),
                                  ("research/schemas", {".json"}), ("ui", {".py", ".html", ".css", ".js"})):
        sources.extend(p for p in (ROOT / directory).glob("*") if p.is_file() and p.suffix in extensions)
    source_hashes = {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(sources))}
    save(out / "source-hashes.json", source_hashes)
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_base_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_hashes_sha256": sha(source_hashes), "artifact_hashes_sha256": sha(artifact_hashes),
        "raw": load(study / "test/raw/progress.json"),
        "raw_audit_status": load(ROOT / "runs/m25-raw-final-audit-v1.job.json")["status"],
        "controlled": load(study / "test/controlled/progress.json"),
        "sensitivity": "NOT_STARTED" if not (study / "test/budget-sensitivity").exists() else "INSPECT_PROGRESS",
        "controller": {"recorded_status": state["status"], "pid": state.get("pid"),
                       "pid_visible_in_current_namespace": Path(f"/proc/{state.get('pid')}").exists(),
                       "interpretation": "Saved RUNNING is not a liveness check; namespace PID visibility does not attest a live controller", "resumed": False},
        "claim_review_completed": claims["completed_by_slot"],
        "discovery_review_completed": discovery["completed_by_slot"],
        "human_agreement": claims["observed_agreement"],
        "pilot30_gate": load(ROOT / "configs/pilot30_selection_protocol.json")["collection_gate"],
        "reconciliation": load(ROOT / "runs/reconciliation-development-v2/summary.json")["paired_nonempty_reference"],
        "new_llm_api_calls": 0, "new_repositories": 0, "new_heldout_predictions": 0,
        "tests": load(out / "test-execution.json") if (out / "test-execution.json").exists() else "NOT_RECORDED",
        "replication_scope": "Local retained snapshots and image IDs required; hashes do not make this a complete portable replication bundle"}
    save(out / "checkpoint.json", summary)
    print(json.dumps({k: summary[k] for k in ("raw_audit_status", "controlled", "claim_review_completed", "source_hashes_sha256")}))


if __name__ == "__main__":
    main()
