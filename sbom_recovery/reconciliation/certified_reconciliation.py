"""Evidence-scoped reconciliation with per-edge explanations."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import json
import hashlib

from packaging.utils import canonicalize_name

from sbom_recovery.core.formats import NativeDocument, sha, validate_native
from .contracts_v2 import ContextKnowledgeV2, ReconciliationDecisionV2, SCOPE
from .certified_evidence import EvidenceView, read_bundle
from .certified_semantics import activation_bounds, marker_bounds

POLICY = "evidence-reconciliation-v2"


def propose(document, context, manifest, acquired):
    view = EvidenceView(document, context, manifest, acquired)
    known, upper = activation_bounds(view, context)
    observed = NativeDocument(document).edges()
    candidates = set(observed)
    for ref, key in view.bound.items():
        for _, _, req in view.distributions[key].requirements:
            for child in view.matching_children(req):
                if child in view.reverse:
                    candidates.add((ref, view.reverse[child]))
    decisions = []
    for source, target in sorted(candidates):
        row = dict(source_ref=source, target_ref=target, operation="abstain", status="UNKNOWN",
                   reason="UNBOUND_OR_AMBIGUOUS_OCCURRENCE")
        if source in view.binding_conflicts or target in view.binding_conflicts:
            row.update(status="CONFLICT", reason="TARGET_IDENTITY_OR_EVIDENCE_CONFLICT")
        parent_key, child_key = view.bound.get(source), view.bound.get(target)
        if parent_key is not None and child_key is not None:
            parent, child = view.distributions[parent_key], view.distributions[child_key]
            matching = [r for r in parent.requirements if canonicalize_name(r[2].name) == child.name]
            active = [r for r in matching if view.unique_child(r[2]) == child_key
                      and marker_bounds(r[2], context, known[parent_key]) is True]
            rule, citations = None, []
            if active:
                rule, citations = "ACTIVE_DECLARATION", [active[0]]
                row.update(status="SUPPORTED", operation="keep" if (source, target) in observed else "add",
                           reason=rule)
            elif (source, target) in observed and parent.complete:
                if not matching:
                    rule = "NO_MATCHING_DECLARATION"
                elif all(marker_bounds(req, context, known[parent_key],
                                       upper[parent_key] if upper is not None else None) is False
                         for _, _, req in matching):
                    rule = "ALL_MATCHING_DECLARATIONS_INACTIVE"
                if rule:
                    row.update(status="REFUTED", operation="retract", reason=rule)
                    citations = matching
            row["explanation"] = {
                "source_id": parent.source_id,
                "parent_metadata_path": parent.path,
                "child_metadata_path": child.path,
                "parent_declarations_complete": parent.complete,
                "known_parent_extras": sorted(known[parent_key]),
                "possible_parent_extras": sorted(upper[parent_key]) if upper is not None else None,
                "requirements": [{"index": index, "declaration": literal,
                    "marker_result": marker_bounds(req, context, known[parent_key],
                        upper[parent_key] if upper is not None else None)}
                    for index, literal, req in (citations if rule else matching)],
            }
            if not rule:
                row["reason"] = "INCOMPLETE_DECLARATIONS_CONTEXT_OR_ENDPOINT_RESOLUTION"
        decisions.append(ReconciliationDecisionV2(**row))
    return decisions, view.diagnostics


def apply_decisions(document, decisions):
    """Apply decisions produced by the reconciliation rules."""
    native = NativeDocument(document)
    retract = {(d.source_ref, d.target_ref) for d in decisions if d.operation == "retract"}
    for decision in decisions:
        if decision.operation == "add":
            native.apply({"operation": "add_dependency", "subject": decision.source_ref, "value": decision.target_ref})
    if native.format == "cyclonedx":
        for row in native.data.get("dependencies", []):
            row["dependsOn"] = [t for t in row.get("dependsOn", []) if (row["ref"], t) not in retract]
        if retract or any(d.operation == "add" for d in decisions):
            native.data["version"] = native.data.get("version", 1) + 1
    else:
        def keep(row):
            edge = row.get("spdxElementId"), row.get("relatedSpdxElement")
            kind = row.get("relationshipType")
            if kind == "DEPENDENCY_OF":
                edge = edge[::-1]
            return kind not in {"DEPENDS_ON", "DEPENDENCY_OF"} or edge not in retract
        native.data["relationships"] = [r for r in native.data.get("relationships", []) if keep(r)]
    return native.data


def reconcile_evidence(document, context, manifest, acquired):
    context = ContextKnowledgeV2.model_validate(context.model_dump() if isinstance(context, ContextKnowledgeV2) else context)
    before = sha(document)
    decisions, diagnostics = propose(document, context, manifest, acquired)
    derived = apply_decisions(document, decisions)
    validation = validate_native(derived)
    evidence_view = EvidenceView(document, context, manifest, acquired)
    if sha(document) != before:
        raise AssertionError("Reconciliation mutated the observation")
    return {"schema_version": "evidence-reconciliation-result-v2", "policy": POLICY,
            "document": derived, "decisions": [d.model_dump() for d in decisions],
            "counts": dict(Counter(d.status for d in decisions)),
            "operations": dict(Counter(d.operation for d in decisions)), "diagnostics": diagnostics,
            "validation": validation,
            "input_sha256": before, "output_sha256": sha(derived), "context_sha256": sha(context.model_dump()),
            "evidence_sha256": sha(evidence_view.manifest.model_dump()),
            "bindings": {"declared": len(evidence_view.manifest.bindings), "bound": len(evidence_view.bound),
                         "installed_occurrences": len(evidence_view.inventory),
                         "complete_identity_inventory": evidence_view.complete_identities()},
            "scope": SCOPE, "path_absence_status": "UNKNOWN", "confidence": None,
            "exploitability": "UNMEASURED", "llm_api_calls": 0}


# Keep existing Python integrations working while the CLI uses the new policy.
reconcile_certified = reconcile_evidence


def run(input_path, context_path, evidence_path, out):
    out = Path(out)
    if out.exists():
        raise FileExistsError("Use a fresh reconciliation output directory")
    input_bytes = Path(input_path).read_bytes()
    document = json.loads(input_bytes)
    context = ContextKnowledgeV2.model_validate_json(Path(context_path).read_text())
    manifest, acquired = read_bundle(evidence_path)
    result = reconcile_evidence(document, context, manifest, acquired)
    derived = result.pop("document")
    out.mkdir(parents=True, exist_ok=False)
    (out / "observation.json").write_bytes(input_bytes)
    def save(name, value):
        (out / name).write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    save("context.json", context.model_dump())
    save("evidence-manifest.json", manifest.model_dump())
    save("reconciled.json" if result["validation"]["valid"] else "candidate-invalid.json", derived)
    save("assessment.json", result)
    save("seal.json", {"policy": POLICY, "input_bytes_sha256": hashlib.sha256(input_bytes).hexdigest(),
                       "prediction_sha256": sha(derived), "assessment_sha256": sha(result),
                       "generated_at": datetime.now(timezone.utc).isoformat(),
                       "context_sha256": result["context_sha256"], "evidence_sha256": result["evidence_sha256"],
                       "reference_labels_read": False, "llm_api_calls": 0})
    return {"policy": POLICY, "counts": result["counts"], "operations": result["operations"],
            "valid": result["validation"]["valid"], "out": str(out)}
