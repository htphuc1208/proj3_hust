"""Oracle-free, three-arm development worker sharing one bound metadata snapshot."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import time

from sbom_recovery.agents.agent import ToolBroker, deterministic_policy
from sbom_recovery.core.contracts import TargetContext
from sbom_recovery.evidence.evidence import EvidenceStore
from sbom_recovery.core.formats import NativeDocument, package_purl, sha, validate_native
from sbom_recovery.gold.gold_contracts import contained
from .reconciliation import load_snapshot, reconcile
from sbom_recovery.evidence.storage import save

METHODS = ("observed", "additive", "additive_reconciliation")


def native_changes(before, after):
    left, right = NativeDocument(before), NativeDocument(after)
    before_ids = {r: package_purl(p, left.format) for r, p in left.packages().items()}
    after_ids = {r: package_purl(p, right.format) for r, p in right.packages().items()}
    return {
        "added_native_edges": sorted(map(list, right.edges() - left.edges())),
        "removed_native_edges": sorted(map(list, left.edges() - right.edges())),
        "added_component_refs": sorted(after_ids.keys() - before_ids.keys()),
        "removed_component_refs": sorted(before_ids.keys() - after_ids.keys()),
        "changed_identity_refs": [
            {"ref": r, "before": before_ids[r], "after": after_ids[r]}
            for r in sorted(before_ids.keys() & after_ids.keys()) if before_ids[r] != after_ids[r]],
    }


def predict(document, context, target, available_at, destination):
    """No reference argument exists. All methods have the same full evidence rights."""
    out = Path(destination)
    out.mkdir(parents=True, exist_ok=False)
    original_sha = sha(document)
    start = time.perf_counter()
    snapshot = load_snapshot(target, context, available_at)
    store = EvidenceStore(out / "evidence")
    try:
        for entry in snapshot["sources"]:
            raw = contained(Path(target), entry["path"]).read_bytes()
            if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
                raise ValueError("Target changed after snapshot validation")
            store.add(raw, source="target:" + entry["path"], kind="target_metadata",
                      target_id=context.target_id, authority="VERIFIED_TARGET",
                      available_at=available_at, availability_kind="OBSERVED_TIME")
        manifest = store.manifest()
        manifest_sha = sha(manifest)
        evidence = {"target_id": context.target_id, "context_sha256": sha(context.model_dump()),
                    "evidence_manifest_sha256": manifest_sha, "sources": snapshot["sources"],
                    "available_at": available_at, "snapshot_diagnostics": snapshot["diagnostics"],
                    "rights": "Same full top-level METADATA bytes; no peers, registry, labels or network",
                    "shared_preparation_seconds": time.perf_counter() - start}
        save(out / "evidence-manifest.json", manifest)
        save(out / "evidence-contract.json", evidence)
        predictions, details = {}, {}
        start = time.perf_counter()
        predictions["observed"] = deepcopy(document)
        details["observed"] = {"status": "COMPLETE", "policy": "OBSERVED_ONLY",
                               "duration_seconds": time.perf_counter() - start}
        start = time.perf_counter()
        try:
            additive = deterministic_policy(ToolBroker(document, store, context, budget=64, active=False))
            predictions["additive"] = additive["verified"].pop("document")
            details["additive"] = additive
        except (ValueError, KeyError, TypeError, OSError) as exc:
            predictions["additive"] = deepcopy(document)
            details["additive"] = {"status": "POLICY_ERROR", "error_type": type(exc).__name__,
                                    "fallback": "ORIGINAL_OBSERVATION"}
        additive_seconds = time.perf_counter() - start
        details["additive"]["duration_seconds"] = additive_seconds
        start = time.perf_counter()
        try:
            assessment = reconcile(predictions["additive"], context, snapshot)
            predictions["additive_reconciliation"] = assessment.pop("document")
            details["additive_reconciliation"] = {"status": details["additive"]["status"],
                "policy": "EXISTING_ADDITIVE_THEN_INACTIVE_RECONCILIATION", "assessment": assessment,
                "additive_prediction_sha256": sha(predictions["additive"])}
        except (ValueError, KeyError, TypeError, OSError) as exc:
            predictions["additive_reconciliation"] = deepcopy(predictions["additive"])
            details["additive_reconciliation"] = {"status": "POLICY_ERROR", "error_type": type(exc).__name__,
                                                   "fallback": "ADDITIVE_PREDICTION"}
        incremental = time.perf_counter() - start
        details["additive_reconciliation"].update(duration_seconds=additive_seconds + incremental,
                                                 incremental_reconciliation_seconds=incremental)
        if sha(store.manifest()) != manifest_sha or sha(document) != original_sha:
            raise ValueError("Evidence manifest or original observation changed")
        matrix = {"schema_version": "paired-reconciliation-matrix-v1", "methods": list(METHODS),
                  "input_sha256": original_sha, "context_sha256": sha(context.model_dump()),
                  "evidence_contract_sha256": sha(evidence), "evidence_manifest_sha256": manifest_sha,
                  "target_id": context.target_id, "reference_labels_read": False, "llm_api_calls": 0,
                  "arms": {}}
        for method in METHODS:
            prediction, detail = predictions[method], details[method]
            validation = validate_native(prediction)
            detail["validation"] = validation
            if not validation["valid"] and detail["status"] == "COMPLETE":
                detail["status"] = "INVALID_NATIVE_OUTPUT"
            # Keep invalid and failed outputs visible; evaluation reports extracted facts separately.
            detail["native_changes_from_observation"] = native_changes(document, prediction)
            detail.update(input_sha256=original_sha, context_sha256=matrix["context_sha256"],
                          evidence_manifest_sha256=manifest_sha,
                          confidence=None, path_absence_status="UNKNOWN")
            directory = out / method
            directory.mkdir()
            save(directory / "prediction.json", prediction)
            save(directory / "details.json", detail)
            seal = {"method": method, "prediction_sha256": sha(prediction), "details_sha256": sha(detail),
                    "input_sha256": original_sha, "context_sha256": matrix["context_sha256"],
                    "evidence_manifest_sha256": manifest_sha, "reference_labels_read": False}
            save(directory / "seal.json", seal)
            matrix["arms"][method] = sha(seal)
        save(out / "matrix-seal.json", matrix)
        return {"status": "SEALED", "methods": {m: details[m]["status"] for m in METHODS}}
    finally:
        store.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("input", "context", "target", "available-at", "out"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    print(json.dumps(predict(json.loads(Path(args.input).read_text()),
        TargetContext.model_validate_json(Path(args.context).read_text()), args.target, args.available_at, args.out)))


if __name__ == "__main__":
    main()
