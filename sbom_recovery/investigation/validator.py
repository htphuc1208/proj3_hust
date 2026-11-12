"""Validate model claims against independently derived, scoped assessments."""
from __future__ import annotations

from .models import Proposal


def validate_proposals(result, proposals, acquired):
    """A model can cite an established claim, never authorize a new fact.

    The engine always computes the output independently. This gate records
    whether explanations/proposals are supported; invalid proposals are retained
    for measuring invalid-action and unsupported-assertion rates.
    """
    known = {r["source_id"] for r in acquired if r.get("status") == "OK"}
    claims = {c.get("claim_id", c.get("id")): c for c in result.get("claims", [])}
    records = []
    for raw in proposals:
        try:
            proposal = Proposal.model_validate(raw)
            claim = claims.get(proposal.claim_id)
            cited = set(proposal.evidence_ids)
            allowed = set((claim or {}).get("support_evidence_ids", (claim or {}).get("evidence_ids", [])))
            if claim is None:
                reason = "UNKNOWN_CLAIM"
            elif claim.get("status") != "SUPPORTED":
                reason = "CLAIM_NOT_SUPPORTED"
            elif not cited <= known or not cited <= allowed:
                reason = "EVIDENCE_DOES_NOT_SUPPORT_CLAIM"
            else:
                reason = "SUPPORTED"
            records.append({"proposal": proposal.model_dump(), "accepted": reason == "SUPPORTED", "reason": reason})
        except ValueError:
            records.append({"proposal": raw, "accepted": False, "reason": "INVALID_PROPOSAL"})
    return {"records": records, "accepted": sum(r["accepted"] for r in records),
            "rejected": sum(not r["accepted"] for r in records),
            "authority": "SCOPED_DETERMINISTIC_RULES"}
