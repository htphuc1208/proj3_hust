"""Draft A+B+E input contracts; declarations are not verified target bindings.

Artifact evidence is optional. Collectors, alignment, field/edge inference and
the multi-document exporter are not implemented by this module.
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from sbom_recovery.core.contracts import StrictModel
from .contracts_v3 import (
    ArtifactTargetV3, BlobReferenceV3, ContextKnowledgeV3, Digest,
    EvidenceInputV3, Identifier, Phase,
)


class ProducerV3(StrictModel):
    name: Identifier
    version: str | None = None
    configuration_sha256: Digest | None = None


class ReconciliationTargetV3(StrictModel):
    target_id: Identifier
    project_ref: Identifier
    revision_ref: str | None = None
    context: ContextKnowledgeV3
    view: Phase
    artifact: ArtifactTargetV3 | None = None


class SbomObservationV3(StrictModel):
    source_id: Identifier
    document: BlobReferenceV3
    format: Literal["CycloneDX", "SPDX"]
    producer: ProducerV3
    # The caller declares intended grouping. Ingest still has to check actual
    # bytes/provenance; matching these labels is not evidence of same-build truth.
    target_id: Identifier
    revision_ref: str | None = None
    context_id: str | None = None
    view: Literal["DECLARED", "RESOLVED", "ARTIFACT", "UNKNOWN"]
    claimed_artifact_sha256: Digest | None = None


class ObservationReferenceV3(StrictModel):
    document_sha256: Digest
    native_ref: Identifier

    def key(self) -> tuple[str, str]:
        return self.document_sha256, self.native_ref


class ConsumerEvaluationV3(StrictModel):
    name: Identifier
    version: Identifier
    configuration: BlobReferenceV3
    advisory_snapshot: BlobReferenceV3
    snapshot_kind: Literal["DATABASE", "RECORDED_RESPONSES"]


class ReconciliationRequestV3(StrictModel):
    schema_version: Literal["sbom-reconciliation-input-v3"] = "sbom-reconciliation-input-v3"
    target: ReconciliationTargetV3
    documents: list[SbomObservationV3] = Field(min_length=2)
    evidence: list[EvidenceInputV3] = Field(default_factory=list)
    policy_id: Identifier
    consumer: ConsumerEvaluationV3 | None = None

    @model_validator(mode="after")
    def one_comparison_group(self):
        ids = [s.source_id for s in self.documents] + [s.source_id for s in self.evidence]
        if len(ids) != len(set(ids)):
            raise ValueError("Source IDs must be unique across documents and evidence")
        for document in self.documents:
            if document.target_id != self.target.target_id:
                raise ValueError("Different targets belong to separate comparison groups")
            if document.view not in {self.target.view, "UNKNOWN"}:
                raise ValueError("Different views cannot be silently merged; use separate groups")
            if document.context_id is not None and document.context_id != self.target.context.context_id:
                raise ValueError("Different contexts belong to separate comparison groups")
            if (document.revision_ref is not None and self.target.revision_ref is not None
                    and document.revision_ref != self.target.revision_ref):
                raise ValueError("Different revisions belong to separate comparison groups")
            if (self.target.artifact is not None and document.claimed_artifact_sha256 is not None
                    and document.claimed_artifact_sha256 != self.target.artifact.artifact.sha256):
                raise ValueError("Claimed artifact digest conflicts with the requested target")
        # Missing context/revision/view information remains missing. We neither
        # fill it from the request nor claim that scope compatibility is verified.
        return self
