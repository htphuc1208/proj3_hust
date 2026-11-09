"""Evidence-scoped, proof-carrying reconciliation of installed declarations."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import json
import hashlib

from packaging.utils import canonicalize_name

from sbom_recovery.core.formats import NativeDocument, sha, validate_native
from .contracts_v2 import ContextKnowledgeV2, DecisionCertificateV2, ReconciliationDecisionV2, SCOPE
from .certified_evidence import EvidenceView, read_bundle
from .certified_semantics import activation_bounds, marker_bounds
from .certificate_checker import check_decisions

POLICY = "certified-reconciliation-v2"


def propose(document, context, manifest, acquired):
    view = EvidenceView(document, context, manifest, acquired)
    known, upper, steps = activation_bounds(view, context)
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
            rule, indices, completeness, invariant = None, [], [], None
            if active:
                rule, indices = "ACTIVE_DECLARATION", [active[0][0]]
                row.update(status="SUPPORTED", operation="keep" if (source, target) in observed else "add",
                           reason=rule)
            elif (source, target) in observed and parent.complete:
                if not matching:
                    rule = "NO_MATCHING_DECLARATION"
                elif all(marker_bounds(req, context, known[parent_key],
                                       upper[parent_key] if upper is not None else None) is False
                         for _, _, req in matching):
                    rule = "ALL_MATCHING_DECLARATIONS_INACTIVE"
                    if not all(marker_bounds(req, context, known[parent_key]) is False for _, _, req in matching):
                        invariant = {k: sorted(v) for k, v in upper.items()}
                if rule:
                    row.update(status="REFUTED", operation="retract", reason=rule)
                    indices = [r[0] for r in matching]
                    completeness = [{"occurrence_id": parent_key, "source_id": parent.source_id}]
            if rule:
                row["certificate"] = DecisionCertificateV2(
                    rule=rule, input_sha256=sha(document), context_sha256=sha(context.model_dump()),
                    evidence_sha256=sha(view.manifest.model_dump()), parent_occurrence=parent_key,
                    child_occurrence=child_key, requirement_indices=indices, completeness=completeness,
                    activation_steps=steps, activation_upper=invariant)
            else:
                row["reason"] = "INCOMPLETE_DECLARATIONS_CONTEXT_OR_ENDPOINT_RESOLUTION"
        decisions.append(ReconciliationDecisionV2(**row))
    return decisions, view.diagnostics


def apply_checked(document, decisions):
    """Internal application; callers must first check the complete decision set."""
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


def reconcile_certified(document, context, manifest, acquired):
    context = ContextKnowledgeV2.model_validate(context.model_dump() if isinstance(context, ContextKnowledgeV2) else context)
    before = sha(document)
    decisions, diagnostics = propose(document, context, manifest, acquired)
    verification = check_decisions(document, context, manifest, acquired, decisions)
    derived = apply_checked(document, decisions)
    validation = validate_native(derived)
    if sha(document) != before:
        raise AssertionError("Reconciliation mutated the observation")
    return {"schema_version": "certified-reconciliation-result-v2", "policy": POLICY,
            "document": derived, "decisions": [d.model_dump() for d in decisions],
            "counts": dict(Counter(d.status for d in decisions)),
            "operations": dict(Counter(d.operation for d in decisions)), "diagnostics": diagnostics,
            "verification": verification, "validation": validation,
            "input_sha256": before, "output_sha256": sha(derived), "context_sha256": sha(context.model_dump()),
            "evidence_sha256": sha(EvidenceView(document, context, manifest, acquired).manifest.model_dump()),
            "scope": SCOPE, "path_absence_status": "UNKNOWN", "confidence": None,
            "exploitability": "UNMEASURED", "llm_api_calls": 0}


def run(input_path, context_path, evidence_path, out):
    out = Path(out)
    if out.exists():
        raise FileExistsError("Use a fresh reconciliation output directory")
    input_bytes = Path(input_path).read_bytes()
    document = json.loads(input_bytes)
    context = ContextKnowledgeV2.model_validate_json(Path(context_path).read_text())
    manifest, acquired = read_bundle(evidence_path)
    result = reconcile_certified(document, context, manifest, acquired)
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
