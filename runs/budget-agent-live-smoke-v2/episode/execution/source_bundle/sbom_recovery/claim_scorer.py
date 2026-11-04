"""Standardized Canonical Claim Scorer for SBOM Recovery Evaluation.

Computes primary scientific metrics defined in the research contract:
1. Verified Recovery Rate (VRR): Proportion of initially missing or conflicting claims recovered correctly.
2. False Assertion Rate (FAR): Proportion of asserted claims that are erroneous according to ground truth.
3. Conflict Resolution Accuracy: Precision specifically on the subset of claims where raw tools disagree.
4. Selective Risk & Abstention (calibration is unmeasured): Coverage vs. Error rate when abstaining on uncertain evidence.
5. Predicate-level Breakdown: Precision, Recall, F1 for name, version, licenseDeclared, depends_on.
"""
from __future__ import annotations

import json
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from .canonical import CanonicalClaim, CanonicalLedger


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class MetricScores(StrictModel):
    tp: int
    fp: int
    fn: int
    precision: float | None
    recall: float | None
    f1: float | None


class ConflictMetrics(StrictModel):
    total_conflicts: int
    correct_resolutions: int
    incorrect_resolutions: int
    abstentions: int
    accuracy_on_covered: float | None
    abstention_rate: float


class ProjectEvaluationReport(StrictModel):
    case_id: str
    strategy: str
    total_gold_claims: int
    total_predicted_claims: int
    total_asserted: int
    total_abstained: int
    overall_metrics: MetricScores
    predicate_metrics: dict[str, MetricScores]
    vrr: float | None
    far: float | None
    conflict_metrics: ConflictMetrics
    coverage: float
    selective_risk: float | None
    unjudged_assertions: int = 0
    known_asserted: int = 0
    evidence_support_rate: float | None = None
    claim_verified_recovery_rate: float | None = None


def claim_key(c):
    return (c.subject, c.predicate, c.layer, c.scope, getattr(c, "target_id", ""),
            getattr(c, "instance_id", ""), getattr(c, "condition", None))


def value(c):
    return json.dumps(c.object, sort_keys=True, ensure_ascii=False)


def scores(tp, fp, fn):
    return MetricScores(tp=tp, fp=fp, fn=fn, precision=tp/(tp+fp) if tp+fp else None,
                        recall=tp/(tp+fn) if tp+fn else None,
                        f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None)


class ClaimScorer:
    """Open-world scoring: an unadjudicated candidate is never a known negative."""

    @classmethod
    def evaluate_case(cls, case_id, strategy, gold_ledger, input_ledger, predicted_ledger, evidence_ledger=None):
        ledgers = [gold_ledger, input_ledger, predicted_ledger]
        if any(l.case_id != case_id or any(c.case_id != case_id for c in l.claims) for l in ledgers):
            raise ValueError("Case mismatch")
        bindings = {getattr(l, "case_manifest_sha256", None) for l in ledgers}
        if len(bindings) != 1:
            raise ValueError("Case manifest mismatch or mixed legacy/v2 ledgers")
        if getattr(gold_ledger, "role", "gold") != "gold":
            raise ValueError("Expected adjudicated gold role")
        positive, negative = set(), set()
        for c in gold_ledger.claims:
            pair = (claim_key(c), value(c))
            if c.status == "verified": positive.add(pair)
            elif c.status == "verified_absent": negative.add(pair)
        positive_by_key = {}
        for k, v in positive: positive_by_key.setdefault(k, set()).add(v)
        if any(len(v)>1 and k[1] != "depends_on" for k,v in positive_by_key.items()) or positive & negative:
            raise ValueError("Gold contains unresolved contradictions")
        asserted = {(claim_key(c), value(c)): c for c in predicted_ledger.claims if c.status == "verified"}
        tps, fps, unjudged = set(), set(), set()
        for pair in asserted:
            k, v = pair
            if pair in positive: tps.add(pair)
            elif pair in negative or (k[1] != "depends_on" and k in positive_by_key): fps.add(pair)
            else: unjudged.add(pair)
        fns = positive - tps
        predicates = sorted({c.predicate for l in ledgers for c in l.claims})
        by_predicate = {p: scores(sum(k[1]==p for k,v in tps), sum(k[1]==p for k,v in fps),
                                  sum(k[1]==p for k,v in fns)) for p in predicates}
        pool = evidence_ledger or input_ledger
        if pool.case_id != case_id or getattr(pool, "case_manifest_sha256", None) not in bindings:
            raise ValueError("Evidence ledger binding mismatch")
        supported = set()
        for pair,c in asserted.items():
            citations = {(e.source_id,e.artifact_sha256,e.locator) for e in c.evidence if e.artifact_sha256}
            available = {(e.source_id,e.artifact_sha256,e.locator) for a in pool.claims
                         if (claim_key(a),value(a)) == pair for e in a.evidence if e.artifact_sha256}
            if citations and citations <= available: supported.add(pair)
        inputs = {}
        for c in input_ledger.claims:
            # Observations have unknown truth status but still expose candidate values.
            inputs.setdefault(claim_key(c), set()).add(value(c))
        recovery = {(k,v) for k,v in positive if
                    (v not in inputs.get(k,set()) if k[1] == "depends_on" else inputs.get(k,set()) != {v})}
        verified_correct = tps & supported if hasattr(gold_ledger, "role") else tps
        rate = len(recovery & verified_correct)/len(recovery) if recovery else None
        conflicts = {k for k,vs in inputs.items() if k[1] != "depends_on" and len(vs)>1 and k in positive_by_key}
        correct = sum(any(k==ck for ck,v in tps) and not any(k==ck for ck,v in fps) for k in conflicts)
        wrong = sum(any(k==ck for ck,v in fps) for k in conflicts)
        abstain = len(conflicts)-correct-wrong
        decisions = {(k, v if k[1]=="depends_on" else None) for k,v in positive}
        covered = {(k,v if k[1]=="depends_on" else None) for k,v in tps|fps} & decisions
        known = len(tps|fps)
        far = len(fps)/known if known else (0.0 if not asserted else None)
        return ProjectEvaluationReport(case_id=case_id, strategy=strategy, total_gold_claims=len(positive),
            total_predicted_claims=len(predicted_ledger.claims), total_asserted=len(asserted),
            total_abstained=sum(c.status=="unknown" for c in predicted_ledger.claims),
            overall_metrics=scores(len(tps),len(fps),len(fns)), predicate_metrics=by_predicate,
            vrr=rate, claim_verified_recovery_rate=rate, far=far,
            conflict_metrics=ConflictMetrics(total_conflicts=len(conflicts),correct_resolutions=correct,
                incorrect_resolutions=wrong,abstentions=abstain,accuracy_on_covered=correct/(correct+wrong) if correct+wrong else None,
                abstention_rate=abstain/len(conflicts) if conflicts else 0.0),
            coverage=len(covered)/len(decisions) if decisions else 0.0, selective_risk=far,
            unjudged_assertions=len(unjudged), known_asserted=known,
            evidence_support_rate=len(supported)/len(asserted) if asserted else None)
