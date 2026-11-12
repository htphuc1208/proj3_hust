"""Draft V3 data boundaries; no collector, trust verifier or inference engine.

Input evidence never grants itself a binding. Result bindings are computed by
future collectors under an explicit policy. These models only validate shape
and selected semantic invariants; they do not prove that observations are true.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal

from packageurl import PackageURL
from pydantic import Field, model_validator

from sbom_recovery.core.contracts import StrictModel

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[str, Field(min_length=1)]
Phase = Literal["DECLARED", "RESOLVED", "ARTIFACT"]
Status = Literal["SUPPORTED", "REFUTED", "CONFLICT", "UNKNOWN"]
SourceKind = Literal[
    "sbom", "artifact_bytes", "manifest", "lockfile", "native_resolution",
    "build_record", "registry_metadata", "registry_archive", "bundler_metafile",
]
PRESENCE = {"metadata_present", "code_present", "unit_present", "contains", "source_contributes"}
UNARY = {"selected", "metadata_present", "code_present", "unit_present", "standard_library"}
ARTIFACT_PREDICATES = PRESENCE | {"standard_library"}


class BlobReferenceV3(StrictModel):
    path: Identifier
    sha256: Digest

    @model_validator(mode="after")
    def logical_path(self):
        # This is a bundle-relative locator. The actual loader must additionally
        # check resolved paths/symlinks and compare file bytes against the digest.
        if "\\" in self.path or ":" in self.path or "\x00" in self.path or any(
            part in {"", ".", ".."} for part in self.path.split("/")
        ):
            raise ValueError("Expected a normalized bundle-relative path")
        return self


class ArtifactTargetV3(StrictModel):
    artifact: BlobReferenceV3
    kind: Literal["java_jar", "js_bundle", "native_binary"]
    boundary: Literal["supplied_artifact"] = "supplied_artifact"


class ContextKnowledgeV3(StrictModel):
    context_id: Identifier
    os: str | None = None
    architecture: str | None = None
    runtimes: dict[str, str | None] = Field(default_factory=dict)
    build_profile: str | None = None
    entrypoint: str | None = None
    # None is unknown; [] is known empty. Keys identify subjects/build roots.
    features_by_subject: dict[str, list[str] | None] = Field(default_factory=dict)


class EvidenceInputV3(StrictModel):
    source_id: Identifier
    blob: BlobReferenceV3
    kind: SourceKind
    claimed_target_sha256: Digest | None = None


class ArtifactRequestV3(StrictModel):
    schema_version: Literal["artifact-reconciliation-input-v3"] = "artifact-reconciliation-input-v3"
    target: ArtifactTargetV3
    sbom: BlobReferenceV3
    sbom_format: Literal["CycloneDX", "SPDX"]
    context: ContextKnowledgeV3
    evidence: list[EvidenceInputV3] = Field(default_factory=list)
    policy_id: Identifier

    @model_validator(mode="after")
    def unique_sources(self):
        unique(self.evidence, "source_id")
        return self


class ClaimScopeV3(StrictModel):
    target_sha256: Digest
    phase: Phase
    unit_domain: Literal[
        "package_identity", "literal_archive_entry", "java_class", "code_footprint",
        "selected_dependency", "declared_dependency", "source_contribution",
    ]
    context_id: Identifier | None = None

    @model_validator(mode="after")
    def selected_scope(self):
        if self.phase == "RESOLVED" and self.context_id is None:
            raise ValueError("Resolved facts require an explicit context ID")
        return self


class EvidenceBindingV3(EvidenceInputV3):
    binding: Literal["DIRECT_ARTIFACT", "MATCHED_OUTPUT", "SUPPLIER_ASSERTED", "UNBOUND", "MISMATCH"]
    observed_target_sha256: Digest | None = None
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def binding_shape(self):
        if self.binding in {"DIRECT_ARTIFACT", "MATCHED_OUTPUT"} and self.observed_target_sha256 is None:
            raise ValueError("Bound results require an observed target digest")
        if self.binding == "DIRECT_ARTIFACT" and self.kind != "artifact_bytes":
            raise ValueError("Direct-artifact evidence must be collected from artifact bytes")
        if self.binding == "MATCHED_OUTPUT" and self.kind not in {
            "build_record", "native_resolution", "bundler_metafile",
        }:
            raise ValueError("Only build/resolution/output records can claim matched output")
        return self


class CoverageV3(StrictModel):
    coverage_id: Identifier
    scope: ClaimScopeV3
    status: Literal["COMPLETE", "PARTIAL", "UNSUPPORTED"]
    evidence_ids: list[Identifier] = Field(min_length=1)
    # Complete entry enumeration does not imply complete semantic identity mapping.
    identity_mapping_complete: bool = False
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def coverage_shape(self):
        if self.status == "COMPLETE" and self.limitations:
            raise ValueError("Coverage with skipped/limited units cannot be complete in that domain")
        return self


class IdentityCandidateV3(StrictModel):
    candidate_id: Identifier
    ecosystem: Identifier
    name: Identifier
    namespace: str | None = None
    version: str | None = None
    origin: str | None = None
    purl: str | None = None

    @model_validator(mode="after")
    def identity_shape(self):
        if self.purl:
            parsed = PackageURL.from_string(self.purl)
            if (parsed.type, parsed.namespace, parsed.name, parsed.version) != (
                self.ecosystem, self.namespace, self.name, self.version,
            ):
                raise ValueError("PURL and identity fields disagree")
        return self


class OccurrenceBindingV3(StrictModel):
    binding_id: Identifier
    occurrence_id: Identifier
    scope: ClaimScopeV3
    candidate_ids: list[Identifier] = Field(default_factory=list)
    resolution: Literal["UNRESOLVED", "UNIQUE", "AMBIGUOUS", "CONFLICT"]
    basis: Literal["TARGET_METADATA", "EXACT_ARTIFACT_MATCH", "MATCHED_BUILD_OUTPUT", "PARTIAL_FINGERPRINT", "UNKNOWN"]
    evidence_ids: list[Identifier] = Field(default_factory=list)

    @model_validator(mode="after")
    def candidate_shape(self):
        if len(set(self.candidate_ids)) != len(self.candidate_ids):
            raise ValueError("Duplicate candidate identity")
        if self.resolution == "UNIQUE" and (
            len(self.candidate_ids) != 1 or self.basis in {"PARTIAL_FINGERPRINT", "UNKNOWN"} or not self.evidence_ids
        ):
            raise ValueError("Unique binding needs one candidate and affirmative binding evidence")
        if self.resolution == "AMBIGUOUS" and len(self.candidate_ids) < 2:
            raise ValueError("Ambiguity requires at least two candidates; a lone weak candidate stays unresolved")
        return self


class ClaimAssessmentV3(StrictModel):
    claim_id: Identifier
    subject: Identifier
    predicate: Literal[
        "identity", "selected", "metadata_present", "code_present", "unit_present",
        "direct_dependency", "contains", "build_input_of", "source_contributes",
        "standard_library", "consumer_identity_alias",
    ]
    object: str | Literal[True]
    scope: ClaimScopeV3
    status: Status
    support_evidence_ids: list[Identifier] = Field(default_factory=list)
    refutation_evidence_ids: list[Identifier] = Field(default_factory=list)
    refutation_coverage_ids: list[Identifier] = Field(default_factory=list)
    rule_id: Identifier
    reason: Identifier

    @model_validator(mode="after")
    def claim_shape(self):
        statuses = {(True, False): "SUPPORTED", (False, True): "REFUTED", (True, True): "CONFLICT", (False, False): "UNKNOWN"}
        if self.status != statuses[(bool(self.support_evidence_ids), bool(self.refutation_evidence_ids))]:
            raise ValueError("Claim status disagrees with admitted positive/negative evidence")
        if self.predicate in UNARY and self.object is not True:
            raise ValueError("Unary claims assert presence/selection; negative evidence sets REFUTED")
        if self.predicate not in UNARY and (not isinstance(self.object, str) or not self.object):
            raise ValueError("Relational/identity claims require a nonempty object ID")
        if self.predicate in ARTIFACT_PREDICATES and self.scope.phase != "ARTIFACT":
            raise ValueError("Footprint/containment claims must use artifact scope")
        if self.predicate in {"selected", "build_input_of"} and self.scope.phase != "RESOLVED":
            raise ValueError("Selection/build-input claims require resolved scope")
        if self.predicate == "direct_dependency" and self.scope.phase == "ARTIFACT":
            raise ValueError("Containment is not a direct-dependency graph")
        if self.predicate in PRESENCE and self.refutation_evidence_ids and not self.refutation_coverage_ids:
            raise ValueError("Presence refutation needs explicitly scoped closure coverage")
        return self


class ProposedChangeV3(StrictModel):
    change_id: Identifier
    operation: Literal["ADD_COMPONENT", "SET_IDENTITY", "ADD_DIRECT_DEPENDENCY", "RETRACT_DIRECT_DEPENDENCY", "CONSUMER_IDENTITY_ALIAS"]
    disposition: Literal["APPLY", "DEFER", "REPORT_ONLY", "NO_CHANGE"]
    scope: ClaimScopeV3
    subject: Identifier
    related_occurrence_id: Identifier | None = None
    claim_ids: list[Identifier] = Field(min_length=1)
    binding_ids: list[Identifier] = Field(default_factory=list)
    before: Any = None
    after: Any = None
    rule_id: Identifier
    reason: Identifier


def unique(items, key):
    values = [getattr(item, key) for item in items]
    if len(set(values)) != len(values):
        raise ValueError(f"Duplicate {key}")


class ArtifactAssessmentV3(StrictModel):
    schema_version: Literal["artifact-reconciliation-assessment-v3"] = "artifact-reconciliation-assessment-v3"
    target: ArtifactTargetV3
    input_sbom_sha256: Digest
    context: ContextKnowledgeV3
    policy_id: Identifier
    export_profile: Literal["PRESERVE_OBSERVATION"] = "PRESERVE_OBSERVATION"
    evidence: list[EvidenceBindingV3] = Field(default_factory=list)
    coverage: list[CoverageV3] = Field(default_factory=list)
    candidates: list[IdentityCandidateV3] = Field(default_factory=list)
    bindings: list[OccurrenceBindingV3] = Field(default_factory=list)
    claims: list[ClaimAssessmentV3] = Field(default_factory=list)
    changes: list[ProposedChangeV3] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    runtime_exploitability: Literal["NOT_ASSESSED"] = "NOT_ASSESSED"

    @model_validator(mode="after")
    def references_and_boundaries(self):
        for items, key in [(self.evidence, "source_id"), (self.coverage, "coverage_id"),
                           (self.candidates, "candidate_id"), (self.bindings, "binding_id"),
                           (self.claims, "claim_id"), (self.changes, "change_id")]:
            unique(items, key)
        sources = {e.source_id: e for e in self.evidence}
        coverage = {c.coverage_id: c for c in self.coverage}
        candidates = {c.candidate_id for c in self.candidates}
        bindings = {b.binding_id: b for b in self.bindings}
        claims = {c.claim_id: c for c in self.claims}
        target = self.target.artifact.sha256

        def refs(ids, index):
            if len(set(ids)) != len(ids) or any(i not in index for i in ids):
                raise ValueError("Duplicate or unresolved reference")

        def anchored(ids):
            return any(sources[i].binding in {"DIRECT_ARTIFACT", "MATCHED_OUTPUT"}
                       and sources[i].observed_target_sha256 == target for i in ids)

        for source in sources.values():
            if source.binding in {"DIRECT_ARTIFACT", "MATCHED_OUTPUT"} and source.observed_target_sha256 != target:
                raise ValueError("Bound evidence belongs to a different target")
        for record in [*self.coverage, *self.bindings, *self.claims, *self.changes]:
            if record.scope.target_sha256 != target:
                raise ValueError("Fact/coverage/change targets another artifact")
            if record.scope.context_id is not None and record.scope.context_id != self.context.context_id:
                raise ValueError("Fact uses another context")
        for item in self.coverage:
            refs(item.evidence_ids, sources)
            if item.status == "COMPLETE" and not anchored(item.evidence_ids):
                raise ValueError("Complete coverage needs target-bound evidence")
        for binding in self.bindings:
            refs(binding.candidate_ids, candidates)
            refs(binding.evidence_ids, sources)
            if binding.resolution == "UNIQUE" and not anchored(binding.evidence_ids):
                raise ValueError("Unique target binding needs target-bound evidence")
        for claim in self.claims:
            if claim.predicate == "identity" and claim.object not in candidates:
                raise ValueError("Identity claim references an unknown candidate")
            # A source can support and refute a claim via different observations.
            refs(claim.support_evidence_ids, sources)
            refs(claim.refutation_evidence_ids, sources)
            refs(claim.refutation_coverage_ids, coverage)
            ids = claim.support_evidence_ids + claim.refutation_evidence_ids
            if claim.scope.phase != "DECLARED" and any(
                side and not anchored(side) for side in [claim.support_evidence_ids, claim.refutation_evidence_ids]
            ):
                raise ValueError("Each polarity of a target fact needs target-bound evidence")
            if any(sources[i].binding == "MISMATCH" for i in ids):
                raise ValueError("Mismatched evidence cannot support a claim about this target")
            for coverage_id in claim.refutation_coverage_ids:
                item = coverage[coverage_id]
                if item.scope != claim.scope or item.status != "COMPLETE":
                    raise ValueError("Refutation coverage must completely cover this exact scope")
                if claim.scope.unit_domain != "literal_archive_entry" and not item.identity_mapping_complete:
                    raise ValueError("Entry enumeration cannot refute semantic identity presence")
        for change in self.changes:
            refs(change.claim_ids, claims)
            refs(change.binding_ids, bindings)
            if change.disposition != "APPLY":
                continue
            assertions = [claims[i] for i in change.claim_ids]
            if any(c.status in {"UNKNOWN", "CONFLICT"} for c in assertions):
                raise ValueError("Unknown/conflicting claims cannot authorize a change")
            bound = [bindings[i] for i in change.binding_ids]
            required = 2 if "DIRECT_DEPENDENCY" in change.operation else 1
            if len({b.occurrence_id for b in bound}) < required or any(b.resolution != "UNIQUE" for b in bound):
                raise ValueError("Applied change requires uniquely bound distinct occurrences")
            subject_bindings = [b for b in bound if b.occurrence_id == change.subject]
            if not subject_bindings:
                raise ValueError("Change subject is not bound by its referenced occurrences")
            local = [c for c in assertions if c.scope == change.scope]
            positive = [c for c in local if c.status == "SUPPORTED" and c.subject == change.subject]
            candidate_ids = {i for b in subject_bindings for i in b.candidate_ids}
            if change.operation in {"ADD_COMPONENT", "SET_IDENTITY"} and not any(
                c.predicate == "identity" and c.object in candidate_ids for c in positive
            ):
                raise ValueError("Identity change needs supported identity of this bound subject")
            if change.operation == "ADD_COMPONENT" and not any(
                c.subject == change.subject and c.predicate in {"code_present", "metadata_present"}
                and c.status == "SUPPORTED" and c.scope.phase == "ARTIFACT" for c in assertions
            ):
                raise ValueError("Adding a component requires evidence of this target occurrence")
            if "DIRECT_DEPENDENCY" in change.operation:
                if not change.related_occurrence_id or change.related_occurrence_id == change.subject or not any(
                    b.occurrence_id == change.related_occurrence_id for b in bound
                ):
                    raise ValueError("Direct dependency requires the distinct bound target endpoint")
                expected = "REFUTED" if change.operation == "RETRACT_DIRECT_DEPENDENCY" else "SUPPORTED"
                if not any(c.subject == change.subject and c.object == change.related_occurrence_id
                           and c.predicate == "direct_dependency" and c.status == expected for c in local):
                    raise ValueError("Only a direct-dependency claim of these endpoints authorizes this edge")
            if change.operation == "CONSUMER_IDENTITY_ALIAS" and not any(
                c.predicate == "consumer_identity_alias" for c in positive
            ):
                raise ValueError("Consumer alias requires a scoped mapping claim")
        return self
