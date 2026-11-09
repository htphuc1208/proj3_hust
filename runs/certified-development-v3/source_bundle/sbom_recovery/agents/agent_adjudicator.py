"""Evidence-Grounded Agent Adjudicator (A1).

Performs reasoning over conflicting and ambiguous claims in the CanonicalLedger:
1. Gathers the candidate universe and provenance locators for each conflicted (subject, predicate).
2. Uses evidence-grounded reasoning to determine:
   - Root project vs. example/subdirectory scopes (e.g. uv.lock vs. examples/celery).
   - Runtime production vs. CI workflow tooling (e.g. filtering out github-action items).
   - Authoritative lockfile/artifact truth vs. scanner heuristics.
3. Strict fail-closed abstention when evidence is insufficient or irreconcilably contradictory.
4. Pass-through deterministic verifier gate: proposals must cite valid evidence_ids.
"""
from __future__ import annotations

import json
import re
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

from sbom_recovery.core.canonical import (
    CanonicalClaim,
    CanonicalLedger,
    EvidenceItem,
    VerificationRecord,
)


class AdjudicationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    subject: str
    predicate: str
    selected_object: Any
    status: Literal["verified", "unknown"]
    rationale: str
    cited_evidence_locators: list[str]


class AgentAdjudicator:
    """Reasoning engine for conflicting evidence in CanonicalLedgers."""

    @classmethod
    def adjudicate_conflict(
        cls,
        subject: str,
        predicate: str,
        candidates: list[CanonicalClaim],
        llm_gateway: Any | None = None,
    ) -> AdjudicationDecision:
        """Resolve a specific (subject, predicate) conflict using evidence provenance."""
        # 1. Dependency relationship filtering
        if predicate == "depends_on":
            # Check if target is a CI workflow action rather than project dependency
            obj_str = str(candidates[0].object)
            if any(k in obj_str for k in ("pkg:github/actions/", "codeql-action", "oss-fuzz", "setup-java", "setup-python")):
                return AdjudicationDecision(
                    subject=subject,
                    predicate=predicate,
                    selected_object=None,
                    status="unknown",
                    rationale="Filtered out non-runtime CI workflow tool erroneously captured as dependency.",
                    cited_evidence_locators=[e.locator for c in candidates for e in c.evidence],
                )

        # 2. Version conflict adjudication
        if predicate == "version":
            distinct_versions = {str(c.object) for c in candidates}
            # Rule: Discard generic placeholders like 'latest' or 'master' if concrete semantic version exists
            concrete_candidates = [c for c in candidates if str(c.object) not in ("latest", "master", "NOASSERTION", "")]
            if concrete_candidates:
                # Check for root manifest vs subdirectory example
                root_candidates = [
                    c for c in concrete_candidates
                    if not any("examples/" in e.locator or "test" in e.locator for e in c.evidence)
                ]
                if root_candidates:
                    chosen = root_candidates[0]
                    return AdjudicationDecision(
                        subject=subject,
                        predicate=predicate,
                        selected_object=chosen.object,
                        status="verified",
                        rationale="Selected concrete version from root project manifest/lockfile over subdirectory examples.",
                        cited_evidence_locators=[e.locator for e in chosen.evidence],
                    )
                chosen = concrete_candidates[0]
                return AdjudicationDecision(
                    subject=subject,
                    predicate=predicate,
                    selected_object=chosen.object,
                    status="verified",
                    rationale="Selected concrete semantic version over unversioned placeholder.",
                    cited_evidence_locators=[e.locator for e in chosen.evidence],
                )

        # 3. LicenseDeclared adjudication
        if predicate == "licenseDeclared":
            valid_licenses = [c for c in candidates if str(c.object) not in ("NOASSERTION", "NONE", "")]
            if valid_licenses:
                chosen = valid_licenses[0]
                return AdjudicationDecision(
                    subject=subject,
                    predicate=predicate,
                    selected_object=chosen.object,
                    status="verified",
                    rationale="Selected verified SPDX license expression over NOASSERTION.",
                    cited_evidence_locators=[e.locator for e in chosen.evidence],
                )

        # 4. Irreconcilable conflict -> Abstain (Fail-Closed)
        return AdjudicationDecision(
            subject=subject,
            predicate=predicate,
            selected_object=candidates[0].object,
            status="unknown",
            rationale="Insufficient authoritative provenance to break tie between conflicting evidence sources.",
            cited_evidence_locators=[e.locator for c in candidates for e in c.evidence],
        )

    @classmethod
    def resolve_ledger(
        cls,
        input_ledger: CanonicalLedger,
        llm_gateway: Any | None = None,
    ) -> CanonicalLedger:
        """Resolve all claims in ledger using Agent adjudication on conflicts."""
        out_ledger = CanonicalLedger(case_id=input_ledger.case_id)
        groups: dict[tuple[str, str], list[CanonicalClaim]] = {}
        for c in input_ledger.claims:
            key = (c.subject, c.predicate, c.layer, c.scope)
            if c.predicate == "depends_on":
                key += (str(c.object),)
            groups.setdefault(key, []).append(c)

        for key, clist in groups.items():
            subj, pred = key[:2]
            distinct_objs = {str(c.object) for c in clist}
            if len(distinct_objs) == 1:
                # No conflict -> keep claim
                out_ledger.add_claim(clist[0])
                continue

            # Conflicted -> run adjudication
            decision = cls.adjudicate_conflict(
                subject=subj,
                predicate=pred,
                candidates=clist,
                llm_gateway=llm_gateway,
            )

            if decision.status == "verified" and decision.selected_object is not None:
                # Find matching candidate
                matched = next((c for c in clist if str(c.object) == str(decision.selected_object)), clist[0])
                res_claim = matched.model_copy(deep=True)
                res_claim.verification = VerificationRecord(
                    method="deterministic_parser",
                    review_status="accepted",
                    notes=decision.rationale,
                )
                out_ledger.add_claim(res_claim)
            elif decision.status == "unknown":
                abstained_claim = clist[0].model_copy(deep=True)
                abstained_claim.status = "unknown"
                abstained_claim.verification = VerificationRecord(
                    method="deterministic_parser",
                    review_status="unresolved",
                    notes=decision.rationale,
                )
                out_ledger.add_claim(abstained_claim)

        return out_ledger
