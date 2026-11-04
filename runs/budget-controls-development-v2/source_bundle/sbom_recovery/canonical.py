"""Canonical Claim Data Model and Evidence Ledger.

This module provides the core data contracts for Evidence-Grounded SBOM Recovery:
- Separating claims into 3 layers: G1 (Source/Manifest), G2 (Resolved Graph), G3 (Artifact).
- Bounding claims with explicit scope: runtime_production, development, test, build, optional.
- Explicit status semantics: verified, verified_absent, unknown, not_applicable.
- Verifiable provenance: source citations, artifact digests, and verification records.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


ClaimStatus = Literal["verified", "verified_absent", "unknown", "not_applicable"]
ClaimLayer = Literal["G1_source", "G2_resolved", "G3_artifact"]
ClaimScope = Literal["runtime_production", "development", "test", "build", "optional", "unknown"]
SourceType = Literal[
    "scanner_sbom",
    "manifest_source",
    "lockfile",
    "native_resolver_report",
    "installed_artifact_metadata",
    "manual_audit",
]
VerificationMethod = Literal[
    "deterministic_parser",
    "native_dry_run_resolver",
    "direct_artifact_inspection",
    "dual_annotator_adjudication",
    "unverified",
]
ReviewStatus = Literal["accepted", "contested", "unresolved"]


class EvidenceItem(StrictModel):
    source_id: str
    source_type: SourceType
    artifact_sha256: str | None = None
    locator: str
    raw_value: Any = None
    recorded_at: str | None = None


class VerificationRecord(StrictModel):
    method: VerificationMethod = "unverified"
    review_status: ReviewStatus = "unresolved"
    annotator: str | None = None
    notes: str | None = None


def compute_claim_id(case_id: str, subject: str, predicate: str, object_val: Any, layer: str, scope: str) -> str:
    """Compute a deterministic hash for a canonical claim."""
    canonical_repr = json.dumps(
        {
            "case_id": case_id,
            "subject": subject,
            "predicate": predicate,
            "object": object_val,
            "layer": layer,
            "scope": scope,
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()


class CanonicalClaim(StrictModel):
    case_id: str
    subject: str
    predicate: str
    object: Any
    layer: ClaimLayer = "G2_resolved"
    scope: ClaimScope = "runtime_production"
    status: ClaimStatus = "verified"
    evidence: list[EvidenceItem] = Field(default_factory=list)
    verification: VerificationRecord = Field(default_factory=VerificationRecord)
    claim_id: str = ""

    @model_validator(mode="after")
    def populate_claim_id(self) -> CanonicalClaim:
        expected_id = compute_claim_id(
            case_id=self.case_id,
            subject=self.subject,
            predicate=self.predicate,
            object_val=self.object,
            layer=self.layer,
            scope=self.scope,
        )
        if not self.claim_id:
            self.claim_id = expected_id
        elif self.claim_id != expected_id:
            raise ValueError(f"Mismatched claim_id: expected {expected_id}, got {self.claim_id}")
        return self


class CanonicalLedger(StrictModel):
    case_id: str
    claims: list[CanonicalClaim] = Field(default_factory=list)

    def add_claim(self, claim: CanonicalClaim) -> None:
        if claim.case_id != self.case_id:
            raise ValueError(f"Claim case_id {claim.case_id} does not match ledger case_id {self.case_id}")
        # If identical claim exists, merge evidence without duplicating
        for existing in self.claims:
            if existing.claim_id == claim.claim_id:
                existing_locators = {json.dumps(e.model_dump(mode="json"), sort_keys=True) for e in existing.evidence}
                for ev in claim.evidence:
                    signature = json.dumps(ev.model_dump(mode="json"), sort_keys=True)
                    if signature not in existing_locators:
                        existing.evidence.append(ev)
                        existing_locators.add(signature)
                return
        self.claims.append(claim)

    def get_claims(
        self,
        subject: str | None = None,
        predicate: str | None = None,
        layer: ClaimLayer | None = None,
        scope: ClaimScope | None = None,
    ) -> list[CanonicalClaim]:
        result = []
        for c in self.claims:
            if subject is not None and c.subject != subject:
                continue
            if predicate is not None and c.predicate != predicate:
                continue
            if layer is not None and c.layer != layer:
                continue
            if scope is not None and c.scope != scope:
                continue
            result.append(c)
        return result

    def find_conflicts(self) -> dict[tuple[str, str], list[CanonicalClaim]]:
        """Identify (subject, predicate) pairs with conflicting object values within the same layer & scope."""
        groups: dict[tuple[str, str, str, str], list[CanonicalClaim]] = {}
        for c in self.claims:
            key = (c.subject, c.predicate, c.layer, c.scope)
            groups.setdefault(key, []).append(c)

        conflicts: dict[tuple[str, str], list[CanonicalClaim]] = {}
        for (subj, pred, _, _), clist in groups.items():
            if pred == "depends_on":
                # Multi-valued relation: a package having multiple dependencies is not a scalar conflict
                continue
            distinct_objects = {json.dumps(c.object, sort_keys=True) for c in clist}
            if len(distinct_objects) > 1:
                conflicts.setdefault((subj, pred), []).extend(clist)
        return conflicts

    def fingerprint(self) -> str:
        """Deterministic digest of all claims in the ledger."""
        payload = self.model_dump(mode="json")
        payload["claims"] = sorted(payload["claims"], key=lambda c: json.dumps(c, sort_keys=True))
        for c in payload["claims"]:
            c["evidence"] = sorted(c["evidence"], key=lambda e: json.dumps(e, sort_keys=True))
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CanonicalLedger:
        return cls.model_validate(data)

    def save(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: Path | str) -> CanonicalLedger:
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls.model_validate(data)
