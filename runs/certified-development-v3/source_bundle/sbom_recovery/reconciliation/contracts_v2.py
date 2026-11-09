"""Explicit knowledge boundaries for certified reconciliation.

Collectors/context authors are trusted inputs, not cryptographic attestations.
Legacy recovery/gold contracts deliberately remain unchanged.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from sbom_recovery.core.contracts import StrictModel
from sbom_recovery.core.formats import sha
from sbom_recovery.gold.gold_contracts import relative_file

MARKER_NAMES = frozenset({
    "os_name", "sys_platform", "platform_machine", "platform_system",
    "platform_release", "platform_version", "python_version", "python_full_version",
    "implementation_name", "implementation_version", "platform_python_implementation",
})
SCOPE = "installed_distribution_declared_direct_requirements"


def timestamp(value: str):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Evidence time requires an explicit timezone")
    return result


class ContextKnowledgeV2(StrictModel):
    schema_version: Literal["reconciliation-context-v2"] = "reconciliation-context-v2"
    target_id: str = Field(min_length=1)
    installation_scope: str
    evidence_cutoff: str
    marker_values: dict[str, str | None] = Field(default_factory=dict)
    # Keys are physical occurrence IDs, never PURLs. None means unknown extras.
    root_requests: dict[str, list[str] | None] = Field(default_factory=dict)
    root_requests_complete: bool = False
    scope: Literal["installed_distribution_declared_direct_requirements"] = SCOPE

    @model_validator(mode="after")
    def coherent(self):
        relative_file(self.installation_scope)
        if self.installation_scope.split("/")[-1] not in {"site-packages", "dist-packages"}:
            raise ValueError("Expected an explicit installation directory")
        timestamp(self.evidence_cutoff)
        if set(self.marker_values) - MARKER_NAMES:
            raise ValueError("Unsupported marker variable; extras are represented separately")
        minor, full = (self.marker_values.get(k) for k in ("python_version", "python_full_version"))
        if minor and full and not full.startswith(minor + "."):
            raise ValueError("Inconsistent Python versions")
        if self.root_requests_complete and any(v is None for v in self.root_requests.values()):
            raise ValueError("Complete requests cannot contain unknown extras")
        return self


class EvidenceSourceV2(StrictModel):
    source_id: str
    path: str
    occurrence_path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bytes: int = Field(ge=0)
    available_at: str
    kind: Literal["installed_metadata", "registry_metadata"] = "installed_metadata"
    acquired: bool = True

    @model_validator(mode="after")
    def located(self):
        relative_file(self.path)
        relative_file(self.occurrence_path)
        timestamp(self.available_at)
        return self


def occurrence_id(target_id: str, path: str) -> str:
    return sha([target_id, path])


class EvidenceManifestV2(StrictModel):
    schema_version: Literal["reconciliation-evidence-v2"] = "reconciliation-evidence-v2"
    target_id: str
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inventory_complete: bool = False
    sources: list[EvidenceSourceV2]
    # Trusted collection is rechecked against the native document's locations.
    bindings: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def unique_sources(self):
        if len({s.source_id for s in self.sources}) != len(self.sources):
            raise ValueError("Duplicate evidence source ID")
        for s in self.sources:
            expected = sha([s.kind, self.target_id, s.occurrence_path, s.sha256])
            if s.source_id != expected:
                raise ValueError("Source ID is not bound to its target/path/bytes")
        return self


class CompletenessClaim(StrictModel):
    occurrence_id: str
    source_id: str
    predicate: Literal["requires_dist"] = "requires_dist"
    rule: Literal["COMPLETE_INSTALLED_METADATA"] = "COMPLETE_INSTALLED_METADATA"


class ActivationStep(StrictModel):
    source_id: str
    requirement_index: int = Field(ge=0)
    child_occurrence: str


class DecisionCertificateV2(StrictModel):
    schema_version: Literal["reconciliation-certificate-v2"] = "reconciliation-certificate-v2"
    rule: Literal["ACTIVE_DECLARATION", "NO_MATCHING_DECLARATION", "ALL_MATCHING_DECLARATIONS_INACTIVE"]
    input_sha256: str
    context_sha256: str
    evidence_sha256: str
    parent_occurrence: str
    child_occurrence: str
    requirement_indices: list[int]
    completeness: list[CompletenessClaim] = Field(default_factory=list)
    activation_steps: list[ActivationStep] = Field(default_factory=list)
    # An inductive upper invariant. None never proves an extra inactive.
    activation_upper: dict[str, list[str]] | None = None


class ReconciliationDecisionV2(StrictModel):
    schema_version: Literal["reconciliation-decision-v2"] = "reconciliation-decision-v2"
    source_ref: str
    target_ref: str
    operation: Literal["add", "retract", "keep", "abstain"]
    status: Literal["SUPPORTED", "REFUTED", "UNKNOWN", "CONFLICT"]
    reason: str
    certificate: DecisionCertificateV2 | None = None

    @model_validator(mode="after")
    def decision_shape(self):
        if self.status in {"UNKNOWN", "CONFLICT"}:
            if self.operation != "abstain" or self.certificate is not None:
                raise ValueError("Uncertain/conflicting evidence cannot authorize a change")
        elif self.certificate is None:
            raise ValueError("A determinate assessment requires a certificate")
        if self.status == "SUPPORTED" and self.operation not in {"add", "keep"}:
            raise ValueError("Supported edge can only be added or kept")
        if self.status == "REFUTED" and self.operation != "retract":
            raise ValueError("Refuted edge must be an observed retraction")
        return self
