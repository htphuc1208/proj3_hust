"""Versioned, strict boundaries shared by the broker, model, and verifier."""
from __future__ import annotations

from typing import Any, Literal
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class TargetContext(StrictModel):
    os_name: str
    sys_platform: str
    platform_machine: str
    python_version: str
    python_full_version: str
    platform_system: str
    active_extras: list[str]
    # Artifact identity and availability horizon are separate from release time.
    target_id: str
    evidence_cutoff: str
    extras_by_purl: dict[str, list[str]] = Field(default_factory=dict)
    root_purls: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def coherent_environment(self):
        if not self.python_full_version.startswith(self.python_version + "."):
            raise ValueError("Python major/minor and full version disagree")
        horizon = datetime.fromisoformat(self.evidence_cutoff.replace("Z", "+00:00"))
        if horizon.tzinfo is None:
            raise ValueError("Evidence cutoff must include a timezone")
        if not self.target_id:
            raise ValueError("Target identity cannot be empty")
        return self


class RecoveryInput(StrictModel):
    schema_version: Literal["recovery-input-v1"] = "recovery-input-v1"
    document: dict[str, Any]
    context: TargetContext | None
    evidence_ids: list[str] = Field(default_factory=list)


class EvidenceRecord(StrictModel):
    schema_version: Literal["evidence-v1"] = "evidence-v1"
    evidence_id: str
    sha256: str
    source: str
    acquired_at: str
    available_at: str | None = None
    availability_kind: Literal["OBSERVED_TIME", "UPPER_BOUND", "UNKNOWN"] = "UNKNOWN"
    target_id: str | None = None
    kind: Literal["registry", "peer_sbom", "target_metadata", "source_file", "build_record"]
    # Grant target authority only in trusted collectors, never from model arguments.
    authority: Literal["SUPPORTED", "VERIFIED_TARGET"] = "SUPPORTED"


class RepairProposal(StrictModel):
    schema_version: Literal["proposal-v1"] = "proposal-v1"
    operation: Literal["set_field", "add_component", "add_dependency"]
    subject: str
    field: str | None = None
    before: Any = None
    value: Any
    evidence_ids: list[str] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def operation_shape(self):
        if self.operation == "set_field" and not self.field:
            raise ValueError("set_field requires a field")
        if self.operation != "set_field" and self.field is not None:
            raise ValueError("Only set_field accepts a field")
        return self


class AgentAction(StrictModel):
    action: Literal["inspect", "search", "read_evidence", "acquire", "verify", "finish"]
    arguments: dict[str, Any] = Field(default_factory=dict)
    proposals: list[RepairProposal] = Field(default_factory=list, max_length=256)
