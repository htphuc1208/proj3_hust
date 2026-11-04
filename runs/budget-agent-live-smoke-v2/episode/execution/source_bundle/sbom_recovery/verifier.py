"""Deterministic policy gate. LLM agreement and evidence hashes alone prove nothing."""
from __future__ import annotations

from copy import deepcopy
import json
from pydantic import ValidationError

from .contracts import RepairProposal
from .formats import NativeDocument, encoded, sha, validate_native

FIELDS = {"name", "version", "versionInfo", "purl", "externalRefs", "licenses", "licenseDeclared",
          "licenseConcluded", "supplier", "originator", "homepage", "description", "downloadLocation",
          "hashes", "checksums", "copyrightText", "fileTypes", "licenseInfoInFiles", "sourceInfo"}


def proposals_from_claims(document, claims):
    native = NativeDocument(document)
    result = []
    for c in sorted(claims, key=lambda c: (c["operation"] != "add_component", c["subject"], str(c["field"]))):
        before = native.index().get(c["subject"], {}).get(c["field"])
        if c["operation"] == "set_field" and c["subject"] not in native.index():
            continue  # The complete independently extracted node is already in add_component.
        if c["operation"] == "set_field" and (c["field"] not in FIELDS or before == c["value"]):
            continue
        if c["operation"] == "add_dependency" and (c["subject"], c["value"]) in native.edges():
            continue
        result.append(RepairProposal(operation=c["operation"], subject=c["subject"], field=c["field"],
                                     before=before, value=c["value"], evidence_ids=c["evidence_ids"]).model_dump())
    return result


def verify(document, store, context, proposals, validate_schema=True, calibration=None):
    original = sha(document)
    native = NativeDocument(document)
    claims = store.claims(document, context)  # Re-derive from digest-checked bytes, never model descriptions.
    accepted, supported, rejected = [], [], []
    seen, touched = set(), {}
    for raw in proposals:
        try:
            p = RepairProposal.model_validate(raw)
        except (ValidationError, TypeError, ValueError):
            rejected.append({"proposal": raw, "reason": "INVALID_PROPOSAL_SCHEMA"})
            continue
        data = p.model_dump()
        key = sha(data)
        if key in seen:
            rejected.append({"proposal": data, "reason": "DUPLICATE_PROPOSAL"})
            continue
        seen.add(key)
        matches = [c for c in claims if all(c[k] == data[k] for k in ("operation", "subject", "field", "value"))
                   and set(c["evidence_ids"]).issubset(p.evidence_ids)]
        if not matches:
            rejected.append({"proposal": data, "reason": "NO_SUPPORTING_FACT"})
            continue
        # Every referenced ID must exist and pass its content digest, including extra citations.
        try:
            for evidence_id in p.evidence_ids:
                store.read(evidence_id)
        except (ValueError, OSError):
            rejected.append({"proposal": data, "reason": "INVALID_EVIDENCE_REFERENCE"})
            continue
        if p.operation == "set_field" and p.field not in FIELDS:
            rejected.append({"proposal": data, "reason": "FIELD_NOT_ALLOWED"})
            continue
        if p.operation == "add_dependency":
            declared = NativeDocument(document).declaration(p.subject)
            if declared is not None and p.value not in declared:
                supported.append({"proposal": data, "status": "CONFLICT", "reason": "CONTRADICTED_DECLARATION"})
                continue
        competing = {encoded(c["value"]) for c in claims if c["authority"] == "VERIFIED_TARGET"
                     and all(c[k] == data[k] for k in ("operation", "subject", "field"))}
        if len(competing) > 1 and p.operation != "add_dependency":
            supported.append({"proposal": data, "status": "CONFLICT", "reason": "CONFLICTING_TARGET_EVIDENCE"})
            continue
        if not any(c["authority"] == "VERIFIED_TARGET" for c in matches):
            supported.append({"proposal": data, "status": "SUPPORTED", "reason": "CONTEXT_UNCERTAIN" if context is None else "NOT_TARGET_VERIFIED"})
            continue
        if calibration is not None:
            from .calibration import prediction_set
            if prediction_set(calibration, 1.)["decision"] != "SUPPORTED":
                supported.append({"proposal": data, "status": "UNKNOWN", "reason": "CONFORMAL_ABSTENTION"})
                continue
        touch = (p.operation, p.subject, p.field)
        if p.operation == "set_field" and touch in touched and touched[touch] != p.value:
            rejected.append({"proposal": data, "reason": "CONFLICTING_PROPOSALS"})
            continue
        candidate = NativeDocument(native.data)
        try:
            candidate.apply(p)
            if len(candidate.issues()) > len(native.issues()):
                raise ValueError("NEW_REFERENCE_ERROR")
        except (KeyError, ValueError, TypeError) as exc:
            rejected.append({"proposal": data, "reason": str(exc)})
            continue
        native = candidate
        touched[touch] = p.value
        accepted.append({"proposal": data, "status": "VERIFIED_TARGET", "evidence_level":
                         1 if p.operation == "add_dependency" else 0})
    validation = validate_native(native.data) if validate_schema else {"valid": not native.issues(), "errors": native.issues()}
    if not validation["valid"]:
        # Atomic output gate: proposals remain reviewable, invalid changes are not exported as repairs.
        supported.extend({**a, "status": "CONFLICT", "reason": "OUTPUT_VALIDATION_FAILED"} for a in accepted)
        accepted = []
        native = NativeDocument(document)
    assert sha(document) == original
    return {"schema_version": "verification-v1", "accepted": accepted, "supported": supported,
            "rejected": rejected, "document": native.data, "validation": validation,
            "input_sha256": original, "output_sha256": sha(native.data),
            "confidence": None, "calibration": calibration or "UNMEASURED", "path_absence_status": "UNKNOWN",
            "unresolved": getattr(store, "last_diagnostics", []),
            "verification_scope": "TARGET_METADATA_DECLARATIONS_ONLY; executable contents and runtime use unverified",
            "openvex_status": "under_investigation"}
