"""Inference entrypoint. No oracle argument or evaluator import exists here."""
from __future__ import annotations

import json
from pathlib import Path

from sbom_recovery.reconciliation.merge_contracts_v3 import ReconciliationRequestV3

from .broker import Broker, fingerprint
from .models import Action, Budget
from .planner import PlanningError


def _next_source(broker, *, adaptive):
    sources = [s for s in broker.catalog.descriptors() if s["source_id"] not in broker.visited]
    unresolved = [c for c in broker.result.get("components", []) if c.get("status") in {"UNKNOWN", "CONFLICT"}]
    # The rule policy uses only descriptors and current assessments, never hidden
    # source payloads. Registry candidates cannot establish target installation.
    priorities = {"native_resolution": 0, "lockfile": 1, "build_record": 2,
                  "manifest": 3, "bundler_metafile": 4, "registry_metadata": 5}
    names = {str(c.get("name", "")).lower() for c in unresolved} - {""}
    for advisory in broker.view().get("advisory_focus", []):
        names.update(str(a.get("package", {}).get("name", "")).lower() for a in advisory.get("affected", []))
    names.discard("")
    def order(source):
        hits = sum(n in source.get("description", "").lower() for n in names) if adaptive else 0
        return (-hits, priorities.get(source["kind"], 9), source["source_id"])
    return min(sources, key=order) if sources else None


def _rule_satisfied(result):
    """A registered stopping heuristic, not a proof no contrary evidence exists."""
    components = result.get("components", [])
    if not components or any(c.get("status") != "SUPPORTED" for c in components) or result.get("conflicts"):
        return False
    edges = result.get("edges", [])
    supported = {(e["source"], e["target"], e["relationship_type"]) for e in edges if e.get("status") == "SUPPORTED"}
    return all(e.get("status") in {"SUPPORTED", "REFUTED"}
               or (e.get("scope") == "unknown" and (e["source"], e["target"], e["relationship_type"]) in supported)
               for e in edges)


def investigate(request, base_dir, *, policy="rule", budget=None, planner=None,
                metadata=True, graph=True, initial_evidence=(), fixed_evidence=False,
                advisory_snapshot=None, advisory_ids=()):
    from .engine import ingest, reconcile
    from .evidence import EvidenceCatalog
    if policy not in {"observed", "deterministic", "rule", "agent", "fixed_llm"}:
        raise ValueError("Unknown investigation policy")
    if policy in {"agent", "fixed_llm"} and planner is None:
        raise ValueError("Agent policies require an explicit live or replay planner")
    request = request if isinstance(request, ReconciliationRequestV3) else ReconciliationRequestV3.model_validate(request)
    state = ingest(request, Path(base_dir))
    catalog = EvidenceCatalog(request, Path(base_dir))
    if advisory_snapshot is None and request.consumer is not None:
        from .evidence import read_frozen_blob
        blob = request.consumer.advisory_snapshot
        advisory_snapshot = json.loads(read_frozen_blob(Path(base_dir), blob.path, blob.sha256, 32 * 1024 * 1024))
    if advisory_snapshot is not None:
        from .security import assess
        assess(state, advisory_snapshot)  # Validate the public advisory envelope before planning.
    broker = Broker(state, catalog, budget or Budget(), metadata=metadata, graph=graph,
                    advisory_snapshot=advisory_snapshot, advisory_ids=advisory_ids)
    # Equal-information studies pass the same collector outputs into each arm.
    # This API is controller-only, never available as a model action.
    broker.acquired = list(initial_evidence)
    broker.visited = {r["source_id"] for r in broker.acquired}
    broker.result = reconcile(state, broker.acquired, metadata=metadata, graph=graph)
    transcript, proposals = [], []
    status = "COMPLETE"
    if policy == "observed":
        metadata = graph = broker.metadata = broker.graph = False
    elif policy in {"deterministic", "rule"} and not fixed_evidence:
        stopped_on_evidence = False
        while broker.remaining()["tool_calls"] and broker.remaining()["seconds"] and broker.remaining()["bytes"]:
            if policy == "rule" and _rule_satisfied(broker.result):
                stopped_on_evidence = True
                break
            source = _next_source(broker, adaptive=policy == "rule")
            if source is None:
                break
            broker.call({"action": "acquire", "source_id": source["source_id"]})
        if not stopped_on_evidence and len(broker.visited) < len(catalog.descriptors()):
            status = "RESOURCE_LIMIT"
    elif policy in {"agent", "fixed_llm"}:
        status = "STEP_LIMIT"
        for step in range(broker.budget.max_steps):
            remaining = broker.remaining()
            if not remaining["seconds"]:
                status = "TIME_LIMIT"
                break
            if len(getattr(planner, "records", [])) >= broker.budget.max_model_calls:
                status = "MODEL_CALL_LIMIT"
                break
            try:
                view = broker.view()
                view["acquisition_enabled"] = not (fixed_evidence or policy == "fixed_llm")
                raw = planner.next_action(view, broker.budget, remaining["seconds"])
                if not broker.remaining()["seconds"]:
                    status = "TIME_LIMIT"
                    break
                action = Action.model_validate(raw)
                if action.action == "finish":
                    proposals = [p.model_dump() for p in action.proposals]
                    transcript.append({"step": step, "action": raw, "status": "FINISHED"})
                    status = "COMPLETE"
                    break
                if not remaining["tool_calls"]:
                    status = "TOOL_LIMIT"
                    break
                if action.action == "acquire" and (fixed_evidence or policy == "fixed_llm"):
                    # Invalid attempts consume an action and remain measurable.
                    response = broker.call({"action": "INVALID_ACQUISITION_IN_FIXED_CONDITION"})
                else:
                    response = broker.call(action.model_dump())
                transcript.append({"step": step, "action": raw, "response": response})
            except PlanningError as exc:
                transcript.append({"step": step, "status": "MODEL_ERROR", "error": str(exc)})
                status = "MODEL_ERROR"
                break
            except (ValueError, TypeError) as exc:
                if broker.remaining()["tool_calls"]:
                    broker.call({"action": "INVALID_MODEL_ACTION", "error_type": type(exc).__name__})
                transcript.append({"step": step, "status": "INVALID_ACTION", "error_type": type(exc).__name__})
    result = broker.finalize(proposals)
    result["schema_version"] = "sbom-investigation-result-v1"
    result["policy"] = policy
    result["status"] = status
    result["investigation"].update(planner_kind=getattr(planner, "kind", "DETERMINISTIC"),
        metadata_enabled=broker.metadata, graph_enabled=broker.graph, fixed_evidence=fixed_evidence or policy == "fixed_llm",
        initial_evidence_ids=[r["source_id"] for r in initial_evidence])
    result["investigation"]["model_records"] = getattr(planner, "records", [])
    return {"prediction": result, "tool_trace": broker.trace, "transcript": transcript,
            "acquired": broker.acquired, "request_sha256": fingerprint(request.model_dump())}


def save_run(run, output, *, snapshot=None):
    from .engine import export
    output = Path(output)
    if snapshot is not None:
        from .security import assess
        run["prediction"]["security"] = assess(run["prediction"], snapshot)
    artifacts = export(run["prediction"])
    if not artifacts.get("validation-report.json", {}).get("valid"):
        raise ValueError("Reconciled output failed native validation")
    output.mkdir(parents=True, exist_ok=False)
    artifacts.update({"prediction.json": run["prediction"], "tool-trace.json": run["tool_trace"],
                      "transcript.json": run["transcript"], "acquired-evidence.json": run["acquired"]})
    if snapshot is not None:
        artifacts["security-report.json"] = run["prediction"]["security"]
    for name, body in artifacts.items():
        (output / name).write_text(json.dumps(body, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    seal = {"schema_version": "investigation-seal-v1", "request_sha256": run["request_sha256"],
            "files": {name: __import__("hashlib").sha256((output / name).read_bytes()).hexdigest() for name in artifacts}}
    (output / "seal.json").write_text(json.dumps(seal, indent=2, sort_keys=True) + "\n")
    return {"out": str(output), "status": run["prediction"]["status"], "policy": run["prediction"]["policy"],
            "components": len(run["prediction"].get("components", [])),
            "edges": len(run["prediction"].get("edges", [])), "seal": str(output / "seal.json")}
