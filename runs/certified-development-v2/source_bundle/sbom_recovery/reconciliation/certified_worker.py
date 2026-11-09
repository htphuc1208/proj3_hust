"""Predict on permitted bundles only; this process has no reference argument."""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import time

from sbom_recovery.core.contracts import TargetContext
from sbom_recovery.core.formats import NativeDocument, sha, validate_native
from sbom_recovery.agents.agent import ToolBroker, deterministic_policy
from sbom_recovery.evidence.evidence import EvidenceStore
from .contracts_v2 import ContextKnowledgeV2
from .certified_evidence import EvidenceView, read_bundle
from .certified_reconciliation import reconcile_certified
from .certified_baselines import metadata_control
from .reconciliation import reconcile

METHODS = ("observed", "legacy_additive", "legacy_reconciliation", "metadata_control", "certified_v2")


def predict(job, out):
    job, out = Path(job), Path(out)
    out.mkdir(parents=True, exist_ok=False)
    def load(name):
        return json.loads((job / name).read_text())
    def save(path, value):
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    document = load("observation.json")
    context = ContextKnowledgeV2.model_validate(load("context.json"))
    manifest, acquired = read_bundle(job / "evidence/manifest.json")
    view = EvidenceView(document, context, manifest, acquired)
    seals = {}
    for method in METHODS:
        started, status = time.perf_counter(), "COMPLETE"
        details = {}
        try:
            if method == "observed":
                prediction = deepcopy(document)
            elif method in {"legacy_additive", "legacy_reconciliation"}:
                if load("job.json")["condition"] == "unknown_context":
                    prediction, status = deepcopy(document), "UNSUPPORTED_PARTIAL_CONTEXT"
                else:
                    legacy_context = TargetContext.model_validate(load("legacy-context.json"))
                    if method == "legacy_additive":
                        store = EvidenceStore(out / "legacy-store")
                        try:
                            for source in manifest.sources:
                                if source.acquired and source.source_id in view.by_source:
                                    store.add(acquired[source.source_id], source="target:" + source.occurrence_path,
                                        kind="target_metadata", target_id=context.target_id, authority="VERIFIED_TARGET",
                                        available_at=source.available_at, availability_kind="OBSERVED_TIME")
                            result = deterministic_policy(ToolBroker(document, store, legacy_context, budget=64, active=False))
                            prediction = result["verified"].pop("document")
                            details = {"accepted": len(result["verified"]["accepted"])}
                        finally:
                            store.close()
                    else:
                        prediction = json.loads((out / "legacy_additive/prediction.json").read_text())
                        items = {f"pkg:pypi/{d.name}@{d.version}": {"path": d.path,
                            "sha256": next(s.sha256 for s in manifest.sources if s.source_id == d.source_id),
                            "purl": f"pkg:pypi/{d.name}@{d.version}", "name": d.name, "version": d.version,
                            "requirements": [(text, req) for _, text, req in d.requirements]}
                            for d in view.distributions.values()}
                        diagnostics = list(view.diagnostics)
                        if len(items) != len(view.distributions):
                            diagnostics.append({"reason": "DUPLICATE_METADATA_IDENTITY"})
                        if not view.complete_inventory():
                            diagnostics.append({"reason": "INCOMPLETE_ACQUIRED_INVENTORY"})
                        snapshot = {"target_id": context.target_id, "items": items, "sources": [],
                            "available_at": load("job.json")["available_at"], "diagnostics": diagnostics}
                        assessment = reconcile(prediction, legacy_context, snapshot)
                        prediction = assessment.pop("document")
                        details = {"counts": assessment["counts"], "decisions": [
                            {"source_ref": r["source_ref"], "target_ref": r["target_ref"],
                             "status": {"CONTRADICTED": "REFUTED"}.get(r["status"], r["status"])}
                            for r in assessment["assessments"]]}
            elif method == "metadata_control":
                prediction, assessments = metadata_control(document, context, manifest, acquired, assessments=True)
                details = {"decisions": assessments, "counts": dict(Counter(d["status"] for d in assessments))}
            else:
                details = reconcile_certified(document, context, manifest, acquired)
                prediction = details.pop("document")
        except Exception as exc:
            status, prediction = "POLICY_ERROR", deepcopy(document)
            details = {"error_type": type(exc).__name__, "reason": str(exc)[:240]}
        details.update(status=status, seconds=time.perf_counter() - started, validation=validate_native(prediction),
                       input_sha256=sha(document), context_sha256=sha(context.model_dump()),
                       evidence_sha256=sha(manifest.model_dump()), reference_labels_read=False, llm_api_calls=0)
        directory = out / method
        directory.mkdir()
        save(directory / "prediction.json", prediction)
        save(directory / "details.json", details)
        seal = {"prediction_sha256": sha(prediction), "details_sha256": sha(details),
                "input_sha256": sha(document), "context_sha256": sha(context.model_dump()),
                "evidence_sha256": sha(manifest.model_dump())}
        save(directory / "seal.json", seal)
        seals[method] = sha(seal)
    save(out / "matrix-seal.json", {"arms": seals, "job_sha256": sha(load("job.json")),
         "reference_labels_read": False, "llm_api_calls": 0})
    return {"status": "SEALED", "methods": list(METHODS)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    print(json.dumps(predict(args.job, args.out)))
