"""Strict actions and resource limits for an investigation."""
from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from sbom_recovery.core.contracts import StrictModel


class Budget(StrictModel):
    max_tool_calls: int = Field(default=10, ge=0, le=10000)
    max_bytes: int = Field(default=1048576, ge=0)
    max_steps: int = Field(default=20, ge=0, le=10000)
    max_seconds: float = Field(default=120.0, gt=0, allow_inf_nan=False)
    max_model_calls: int = Field(default=20, ge=0)
    max_tokens: int = Field(default=32768, ge=0)
    max_cost_usd: float = Field(default=1.0, ge=0, allow_inf_nan=False)
    # Explicit, frozen experiment assumptions; no current-price inference.
    input_usd_per_million: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    output_usd_per_million: float | None = Field(default=None, ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def pricing_pair(self):
        if (self.input_usd_per_million is None) != (self.output_usd_per_million is None):
            raise ValueError("Provide both input and output prices, or neither")
        return self


class Proposal(StrictModel):
    claim_id: str = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)


class Action(StrictModel):
    action: Literal["acquire", "inspect", "match_advisories", "verify", "finish"]
    source_id: str | None = None
    subject_id: str | None = None
    proposals: list[Proposal] = Field(default_factory=list, max_length=256)
    reason: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def arguments(self):
        if (self.action == "acquire") != (self.source_id is not None):
            raise ValueError("Only acquire requires a source_id")
        if (self.action == "inspect") != (self.subject_id is not None):
            raise ValueError("Only inspect requires a subject_id")
        if self.action in {"acquire", "inspect", "match_advisories"} and self.proposals:
            raise ValueError("Evidence tools cannot assert claims")
        return self
