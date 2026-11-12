"""Budgeted evidence access and an append-only investigation ledger."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import time

from .models import Action, Budget
from .validator import validate_proposals


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


class Broker:
    def __init__(self, state, catalog, budget=None, *, metadata=True, graph=True,
                 advisory_snapshot=None, advisory_ids=(), clock=time.monotonic):
        from .engine import reconcile
        self.state, self.catalog = deepcopy(state), catalog
        self.budget = budget or Budget()
        self.metadata, self.graph, self.clock = metadata, graph, clock
        self.advisory_snapshot = deepcopy(advisory_snapshot)
        self.advisory_ids = set(advisory_ids)
        self.started = clock()
        self.acquired, self.trace, self.visited = [], [], set()
        self.bytes_used = 0
        self.result = reconcile(self.state, [], metadata=metadata, graph=graph)

    def remaining(self):
        return {"tool_calls": max(0, self.budget.max_tool_calls - len(self.trace)),
                "bytes": max(0, self.budget.max_bytes - self.bytes_used),
                "seconds": max(0.0, self.budget.max_seconds - (self.clock() - self.started))}

    def view(self):
        focus = []
        if self.advisory_snapshot is not None:
            for advisory in self.advisory_snapshot.get("advisories", []):
                aliases = [advisory.get("id"), *advisory.get("aliases", [])]
                if self.advisory_ids and not self.advisory_ids.intersection(aliases):
                    continue
                focus.append({"advisory_id": advisory.get("id"), "aliases": advisory.get("aliases", []),
                    "affected": advisory.get("affected", [])})
        components = sorted(self.result.get("components", []), key=lambda c: (
            c.get("status") not in {"CONFLICT", "UNKNOWN"}, not c.get("root", False), c["id"]))
        selected = components[:40]
        refs = {c["id"] for c in selected}
        descriptors = self.catalog.descriptors()
        compact = {"components": [{k: c.get(k) for k in (
            "id", "ecosystem", "name", "version", "purl", "locator", "status", "binding", "field_candidates", "evidence_ids")}
            for c in selected], "component_count": len(components),
            "edges": [deepcopy(e) for e in self.result.get("edges", []) if e["source"] in refs or e["target"] in refs][:60],
            "claims": [deepcopy(c) for c in self.result.get("claims", []) if c.get("subject") in refs][:60],
            "conflicts": deepcopy(self.result.get("conflicts", [])[:20]),
            "issues": deepcopy(self.result.get("issues", [])[:20]), "roots": self.result.get("roots", [])}
        history = []
        for row in self.trace[-4:]:
            response = row["response"]
            summary = {k: deepcopy(response[k]) for k in (
                "status", "source_id", "error", "limitations", "artifact_digest", "records", "accepted", "rejected") if k in response}
            if "facts" in response:
                summary["fact_counts"] = {k: len(response["facts"].get(k, [])) for k in ("components", "edges", "coverage")}
            if "assessment" in response:
                summary["matching_summary"] = response["assessment"].get("summary", {})
                summary["findings"] = response["assessment"].get("findings", [])[:20]
            if "inspection" in response:
                summary["inspection"] = deepcopy(response["inspection"])
            history.append({"action": row["action"], "response": summary})
        return {"target": self.state["target"], "catalog": descriptors[:64], "catalog_count": len(descriptors),
                "catalog_next": "catalog:64" if len(descriptors) > 64 else None,
                "acquired_source_ids": sorted(self.visited), "remaining": self.remaining(),
                "advisory_focus": focus,
                "assessment": compact, "tool_history": history,
                "content_role": "UNTRUSTED_DATA"}

    def inspect(self, subject):
        if subject.startswith("catalog:"):
            offset = int(subject.split(":", 1)[1])
            if offset < 0:
                raise ValueError("Negative catalog offset")
            rows = self.catalog.descriptors()
            inspection = {"catalog": rows[offset:offset + 64], "catalog_count": len(rows),
                          "catalog_next": "catalog:" + str(offset + 64) if offset + 64 < len(rows) else None}
        else:
            component = next((c for c in self.result.get("components", []) if c["id"] == subject), None)
            if component is None:
                raise ValueError("Unknown component ID")
            ids = set(component.get("observation_ids", []))
            inspection = {"component": component, "observations": [o for o in self.state.get("observations", [])
                if o["observation_id"] in ids], "claims": [c for c in self.result.get("claims", []) if c.get("subject") == subject]}
        raw = json.dumps(inspection, ensure_ascii=False).encode()
        if len(raw) > min(16384, self.remaining()["bytes"]):
            return {"status": "ERROR", "error": "INSPECTION_EXCEEDS_OUTPUT_BUDGET"}
        self.bytes_used += len(raw)
        return {"status": "OK", "inspection": deepcopy(inspection), "bytes_returned": len(raw),
                "content_role": "UNTRUSTED_DATA"}

    def call(self, raw):
        from .engine import reconcile
        remaining = self.remaining()
        if not remaining["tool_calls"] or not remaining["seconds"]:
            return {"status": "ERROR", "error": "BUDGET_EXHAUSTED"}
        started = self.clock()
        try:
            action = Action.model_validate(raw)
            if action.action == "finish":
                raise ValueError("Finish is a controller action, not an acquisition tool")
            if action.action == "verify":
                response = {"status": "OK", **validate_proposals(self.result,
                    [p.model_dump() for p in action.proposals], self.acquired)}
            elif action.action == "inspect":
                response = self.inspect(action.subject_id)
            elif action.action == "match_advisories":
                if self.advisory_snapshot is None:
                    response = {"status": "ERROR", "error": "NO_FROZEN_ADVISORY_SNAPSHOT"}
                else:
                    from .security import assess
                    response = {"status": "OK", "assessment": assess(self.result, self.advisory_snapshot),
                                "content_role": "UNTRUSTED_DATA"}
            elif action.source_id in self.visited:
                response = {"status": "ERROR", "error": "ALREADY_ACQUIRED"}
            elif remaining["bytes"] == 0:
                response = {"status": "ERROR", "error": "BYTE_BUDGET_EXHAUSTED"}
            else:
                response = self.catalog.acquire(action.source_id, remaining_bytes=remaining["bytes"])
                size = response.get("bytes_returned", 0)
                if type(size) is not int or not 0 <= size <= remaining["bytes"]:
                    raise ValueError("Evidence collector violated byte budget")
                self.bytes_used += size
                self.visited.add(action.source_id)
                self.acquired.append(deepcopy(response))
                self.result = reconcile(self.state, self.acquired, metadata=self.metadata, graph=self.graph)
        except (ValueError, TypeError, KeyError, OSError) as exc:
            response = {"status": "ERROR", "error": type(exc).__name__ + ": " + str(exc)[:300]}
        row = {"sequence": len(self.trace), "action": deepcopy(raw), "response": deepcopy(response),
               "duration_seconds": self.clock() - started,
               "previous_sha256": self.trace[-1]["sha256"] if self.trace else None}
        row["sha256"] = fingerprint(row)
        self.trace.append(row)
        return response

    def finalize(self, proposals=()):
        from .engine import reconcile
        # Recompute independently of cached/model-supplied assessments.
        result = reconcile(self.state, deepcopy(self.acquired), metadata=self.metadata, graph=self.graph)
        result["proposal_validation"] = validate_proposals(result, proposals, self.acquired)
        result["investigation"] = {"budget": self.budget.model_dump(), "usage": {
            "tool_calls": len(self.trace), "bytes": self.bytes_used,
            "seconds": self.clock() - self.started}, "trace_sha256": fingerprint(self.trace),
            "oracle_access": False, "path_absence": "UNKNOWN"}
        if self.advisory_snapshot is not None:
            result["investigation"]["advisory_snapshot_sha256"] = fingerprint(self.advisory_snapshot)
            result["investigation"]["focused_advisory_ids"] = sorted(self.advisory_ids)
        return result
