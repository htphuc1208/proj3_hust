"""Check supplied proof obligations, independently of the proposal generator.

This module never imports certified_reconciliation or activation_bounds. It
checks a finite lower derivation and an inductive upper invariant, not the
generator's choice of fixed-point algorithm. The parser/marker evaluator and
trusted collector/context assertions are the explicitly shared trusted base.
"""
from __future__ import annotations

from packaging.utils import canonicalize_name

from sbom_recovery.core.formats import NativeDocument, sha
from .contracts_v2 import ContextKnowledgeV2, ReconciliationDecisionV2
from .certified_evidence import EvidenceView
from .certified_semantics import initial_extras, marker_bounds


def check_activation(certificate, view, context):
    lower = initial_extras(context, view.inventory)
    for step in certificate.activation_steps:
        item = view.by_source.get(step.source_id)
        if item is None or view.distributions.get(item.occurrence) != item:
            raise ValueError("Activation step has unbound/conflicting evidence")
        declaration = next((r for r in item.requirements if r[0] == step.requirement_index), None)
        if declaration is None:
            raise ValueError("Activation citation does not exist")
        req = declaration[2]
        if (view.unique_child(req) != step.child_occurrence
                or marker_bounds(req, context, lower[item.occurrence]) is not True):
            raise ValueError("Activation step is not justified by earlier facts")
        lower[step.child_occurrence].update(canonicalize_name(e) for e in req.extras)
    if certificate.activation_upper is None:
        return lower, None
    upper = {k: {canonicalize_name(e) for e in v} for k, v in certificate.activation_upper.items()}
    if (not context.root_requests_complete or not view.complete_inventory()
            or set(context.root_requests) - view.inventory or set(upper) != view.inventory):
        raise ValueError("Extra upper bound lacks complete inventory/requests")
    if any(not values <= upper[key] for key, values in lower.items()):
        raise ValueError("Extra upper bound omits known activations")
    # Closure is sufficient; a minimal upper invariant is not required.
    for key, item in view.distributions.items():
        for _, _, req in item.requirements:
            if not req.extras or marker_bounds(req, context, set(), upper[key]) is False:
                continue
            matches = view.matching_children(req)
            if req.url or not matches:
                raise ValueError("Extra activation frontier is unresolved")
            extras = {canonicalize_name(e) for e in req.extras}
            if any(not extras <= upper[child] for child in matches):
                raise ValueError("Extra upper bound is not inductive")
    return lower, upper


def check_decision(document, context, manifest, acquired, decision, *, view=None):
    context = ContextKnowledgeV2.model_validate(context.model_dump())
    decision = ReconciliationDecisionV2.model_validate(
        decision.model_dump() if isinstance(decision, ReconciliationDecisionV2) else decision)
    view = view or EvidenceView(document, context, manifest, acquired)
    if decision.operation == "abstain":
        return {"valid": True, "authorizes_change": False}
    certificate = decision.certificate
    if (certificate.input_sha256 != sha(document)
            or certificate.context_sha256 != sha(context.model_dump())
            or certificate.evidence_sha256 != sha(view.manifest.model_dump())):
        raise ValueError("Certificate is stale or belongs to another input")
    parent_key, child_key = (view.bound.get(r) for r in (decision.source_ref, decision.target_ref))
    if (parent_key is None or child_key is None
            or parent_key != certificate.parent_occurrence or child_key != certificate.child_occurrence):
        raise ValueError("Certificate endpoints are not physically bound")
    parent, child = (view.distributions[k] for k in (parent_key, child_key))
    observed = (decision.source_ref, decision.target_ref) in NativeDocument(document).edges()
    if (decision.operation in {"keep", "retract"} and not observed) or (decision.operation == "add" and observed):
        raise ValueError("Stale native-edge precondition")
    lower, upper = check_activation(certificate, view, context)
    matching = [r for r in parent.requirements if canonicalize_name(r[2].name) == child.name]
    if certificate.rule == "ACTIVE_DECLARATION":
        if (decision.status != "SUPPORTED" or len(certificate.requirement_indices) != 1
                or certificate.completeness or certificate.activation_upper is not None):
            raise ValueError("Invalid positive decision shape")
        row = next((r for r in matching if r[0] == certificate.requirement_indices[0]), None)
        if (row is None or view.unique_child(row[2]) != child_key
                or marker_bounds(row[2], context, lower[parent_key]) is not True):
            raise ValueError("Positive declaration/endpoint/guard is not established")
    else:
        if decision.status != "REFUTED" or decision.operation != "retract" or not parent.complete:
            raise ValueError("Negative decision lacks complete parent declarations")
        expected = [{"occurrence_id": parent_key, "source_id": parent.source_id,
                     "predicate": "requires_dist", "rule": "COMPLETE_INSTALLED_METADATA"}]
        if [c.model_dump() for c in certificate.completeness] != expected:
            raise ValueError("Missing/incorrect completeness obligation")
        if certificate.requirement_indices != [r[0] for r in matching]:
            raise ValueError("Negative citation omits matching declarations")
        if certificate.rule == "NO_MATCHING_DECLARATION":
            if matching:
                raise ValueError("Matching declaration exists")
        elif not matching or any(marker_bounds(req, context, lower[parent_key],
                                  upper[parent_key] if upper is not None else None) is not False
                                 for _, _, req in matching):
            raise ValueError("At least one declaration may be active")
    return {"valid": True, "authorizes_change": decision.operation in {"add", "retract"}}


def check_decisions(document, context, manifest, acquired, decisions):
    view = EvidenceView(document, context, manifest, acquired)
    checked, seen = [], set()
    for raw in decisions:
        decision = ReconciliationDecisionV2.model_validate(
            raw.model_dump() if isinstance(raw, ReconciliationDecisionV2) else raw)
        edge = decision.source_ref, decision.target_ref
        if edge in seen:
            raise ValueError("Multiple decisions for the same native edge")
        seen.add(edge)
        checked.append(check_decision(document, context, manifest, acquired, decision, view=view))
    return {"valid": True, "decisions": len(checked),
            "authorized_changes": sum(c["authorizes_change"] for c in checked),
            "trusted_base": ["native parser", "packaging marker semantics", "collector/context assertions"]}
