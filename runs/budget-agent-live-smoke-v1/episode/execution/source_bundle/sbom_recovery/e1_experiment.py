"""Experiment E1 Engine: Same Evidence, Different Decision.

Evaluates deterministic decision strategies over frozen evidence ledgers:
- B0: Priority (Project priority baseline; not the original sbom-unifier; uses source hierarchy: manifest_spdx > syft > trivy > dependency_graph)
- B1: Majority (Votes across independent tool sources, abstains on tie)
- B2: Field-Aware Rules (Authoritative provenance, scope filtering, uncalibrated abstention)
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

from .canonical import (
    CanonicalClaim,
    CanonicalLedger,
    EvidenceItem,
    VerificationRecord,
)

StrategyName = Literal["B0_priority", "B1_majority", "B2_field_aware"]

TOOL_PRIORITY_ORDER = [
    "manifest_spdx",
    "syft",
    "trivy",
    "dependency_graph",
]


class ResolutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    strategy: StrategyName
    resolved_ledger: CanonicalLedger
    total_decisions: int
    conflict_decisions: int
    abstentions: int


class E1DecisionEngine:
    """Executes decision strategies on frozen CanonicalLedger without acquiring new tools."""

    @classmethod
    def resolve_b0_priority(cls, input_ledger: CanonicalLedger) -> ResolutionResult:
        """B0: Project priority baseline; not the original sbom-unifier; uses fixed-priority merging."""
        out_ledger = CanonicalLedger(case_id=input_ledger.case_id)
        groups = cls._group_claims(input_ledger)

        total_decisions = len(groups)
        conflict_decisions = 0
        abstentions = 0

        for key, clist in groups.items():
            subj, pred = key[:2]
            distinct_objs = {str(c.object) for c in clist}
            is_conflict = len(distinct_objs) > 1
            if is_conflict:
                conflict_decisions += 1

            # In sbom-unifier, relationships are naively unioned
            if pred == "depends_on":
                for c in clist:
                    out_ledger.add_claim(c)
                continue

            # Pick claim matching highest priority tool in TOOL_PRIORITY_ORDER
            chosen = None
            for tool in TOOL_PRIORITY_ORDER:
                for c in clist:
                    sources = [e.source_id for e in c.evidence]
                    if tool in sources:
                        chosen = c
                        break
                if chosen is not None:
                    break

            if chosen is None:
                chosen = clist[0]

            out_ledger.add_claim(chosen)

        return ResolutionResult(
            strategy="B0_priority",
            resolved_ledger=out_ledger,
            total_decisions=total_decisions,
            conflict_decisions=conflict_decisions,
            abstentions=abstentions,
        )

    @classmethod
    def resolve_b1_majority(cls, input_ledger: CanonicalLedger) -> ResolutionResult:
        """B1: Majority voting across tool sources."""
        out_ledger = CanonicalLedger(case_id=input_ledger.case_id)
        groups = cls._group_claims(input_ledger)

        total_decisions = len(groups)
        conflict_decisions = 0
        abstentions = 0

        for key, clist in groups.items():
            subj, pred = key[:2]
            distinct_objs = {str(c.object) for c in clist}
            is_conflict = len(distinct_objs) > 1
            if is_conflict:
                conflict_decisions += 1

            if pred == "depends_on":
                # For dependency edge, require at least 2 tools to agree, else drop
                sources_count = len({e.source_id for c in clist for e in c.evidence})
                if sources_count >= 2:
                    out_ledger.add_claim(clist[0])
                else:
                    abstentions += 1
                continue

            # Count votes by distinct object value
            vote_counter: Counter[str] = Counter()
            obj_map: dict[str, CanonicalClaim] = {}
            for c in clist:
                obj_key = str(c.object)
                # Count independent sources
                n_sources = len({e.source_id for e in c.evidence})
                vote_counter[obj_key] += n_sources
                obj_map[obj_key] = c

            most_common = vote_counter.most_common(2)
            if not most_common:
                continue

            # Check for strict winner
            winner_key, winner_votes = most_common[0]
            if len(most_common) > 1 and most_common[1][1] == winner_votes:
                # Tie -> Abstain
                abstentions += 1
                abstained_claim = clist[0].model_copy(deep=True)
                abstained_claim.status = "unknown"
                out_ledger.add_claim(abstained_claim)
            else:
                out_ledger.add_claim(obj_map[winner_key])

        return ResolutionResult(
            strategy="B1_majority",
            resolved_ledger=out_ledger,
            total_decisions=total_decisions,
            conflict_decisions=conflict_decisions,
            abstentions=abstentions,
        )

    @classmethod
    def resolve_b2_field_aware(cls, input_ledger: CanonicalLedger) -> ResolutionResult:
        """B2: Field-aware deterministic rules (source authority + scope filter + uncalibrated abstention)."""
        out_ledger = CanonicalLedger(case_id=input_ledger.case_id)
        groups = cls._group_claims(input_ledger)

        total_decisions = len(groups)
        conflict_decisions = 0
        abstentions = 0

        for key, clist in groups.items():
            subj, pred = key[:2]
            distinct_objs = {str(c.object) for c in clist}
            is_conflict = len(distinct_objs) > 1
            if is_conflict:
                conflict_decisions += 1

            # Rule 1: Filter out non-runtime tooling from relationships
            if pred == "depends_on":
                for c in clist:
                    obj_str = str(c.object)
                    # Filter out CI/Workflow actions erroneously injected into dependency graphs
                    if "actions/" in obj_str or "codeql-action" in obj_str or "oss-fuzz" in obj_str:
                        continue
                    # Filter out test scope if marked in locator
                    is_test_scope = any("scope: test" in str(e.raw_value) or "devDependencies" in e.locator for e in c.evidence)
                    if is_test_scope:
                        continue
                    out_ledger.add_claim(c)
                continue

            # Rule 2: Version selection
            if pred == "version":
                # Prefer specific semantic version over 'latest' or 'master'
                valid_versions = [c for c in clist if str(c.object) not in ("latest", "master", "NOASSERTION", "")]
                if valid_versions:
                    # Filter out example / subproject versions if root lockfile / manifest is present
                    root_versions = [c for c in valid_versions if not any("examples/" in e.locator for e in c.evidence)]
                    candidate_pool = root_versions if root_versions else valid_versions
                    
                    # If multiple distinct root versions remain without clear priority -> Abstain
                    distinct_cands = {str(c.object) for c in candidate_pool}
                    if len(distinct_cands) > 1:
                        abstentions += 1
                        abstained_claim = candidate_pool[0].model_copy(deep=True)
                        abstained_claim.status = "unknown"
                        out_ledger.add_claim(abstained_claim)
                        continue
                    out_ledger.add_claim(candidate_pool[0])
                    continue

            # Rule 3: Declared license
            if pred == "licenseDeclared":
                valid_licenses = [c for c in clist if str(c.object) not in ("NOASSERTION", "NONE", "")]
                if valid_licenses:
                    out_ledger.add_claim(valid_licenses[0])
                    continue

            # Default fallback: pick candidate supported by most sources, else abstain
            sources_per_claim = [(len({e.source_id for e in c.evidence}), c) for c in clist]
            sources_per_claim.sort(key=lambda x: x[0], reverse=True)
            top_sources, top_claim = sources_per_claim[0]
            if len(sources_per_claim) > 1 and sources_per_claim[1][0] == top_sources and str(sources_per_claim[1][1].object) != str(top_claim.object):
                abstentions += 1
                abstained_claim = top_claim.model_copy(deep=True)
                abstained_claim.status = "unknown"
                out_ledger.add_claim(abstained_claim)
            else:
                out_ledger.add_claim(top_claim)

        return ResolutionResult(
            strategy="B2_field_aware",
            resolved_ledger=out_ledger,
            total_decisions=total_decisions,
            conflict_decisions=conflict_decisions,
            abstentions=abstentions,
        )

    @staticmethod
    def _group_claims(ledger: CanonicalLedger) -> dict[tuple[str, str], list[CanonicalClaim]]:
        groups: dict[tuple[str, str], list[CanonicalClaim]] = {}
        for c in ledger.claims:
            key = (c.subject, c.predicate, c.layer, c.scope, getattr(c, "target_id", ""), getattr(c, "instance_id", ""))
            if c.predicate == "depends_on":
                key += (str(c.object),)
            groups.setdefault(key, []).append(c)
        return groups
