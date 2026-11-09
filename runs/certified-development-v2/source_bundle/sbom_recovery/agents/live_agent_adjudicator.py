"""Live LLM Agent Adjudicator for Viettel Netmind Gateway.

Connects to https://stream-netmind.viettel.vn/gateway/v1 using NETMIND_API_KEY
to perform deep context adjudication on conflicting and ambiguous SBOM claims.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
import httpx

from sbom_recovery.core.canonical import (
    CanonicalClaim,
    CanonicalLedger,
    EvidenceItem,
    VerificationRecord,
)

DEFAULT_GATEWAY_URL = "https://stream-netmind.viettel.vn/gateway/v1"
DEFAULT_MODEL = "Qwen/Qwen3.6-35B-A3B-FP8"


class LiveAgentAdjudicator:
    """Invokes Viettel Netmind LLM Gateway to adjudicate ambiguous claims."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_GATEWAY_URL,
        model: str = DEFAULT_MODEL,
        timeout: float = 120.0,
    ):
        self.api_key = api_key if api_key is not None else os.environ.get("NETMIND_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout)

    def close(self):
        self.client.close()

    def adjudicate_conflict_live(
        self,
        case_id: str,
        subject: str,
        predicate: str,
        candidates: list[CanonicalClaim],
    ) -> dict[str, Any]:
        """Send conflict prompt to LLM and return structured adjudication decision."""
        if not self.api_key:
            return {
                "status": "unknown",
                "selected_object": None,
                "rationale": "NETMIND_API_KEY not provided",
                "evidence_locators": [],
            }

        candidates_payload = []
        for i, c in enumerate(candidates):
            candidates_payload.append({
                "candidate_index": i + 1,
                "value": c.object,
                "evidence": [
                    {
                        "source_id": e.source_id,
                        "source_type": e.source_type,
                        "locator": e.locator,
                        "raw_value": str(e.raw_value)[:200],
                    }
                    for e in c.evidence
                ],
            })

        system_prompt = (
            "You are a Principal Software Supply Chain Security Researcher (A* Tier-1 Standard).\n"
            "Your task is to adjudicate conflicting SBOM claims between multiple scanners.\n"
            "Rules:\n"
            "1. Ground Truth Priority: Project root lockfiles (e.g., uv.lock, package-lock.json) and artifact METADATA override examples and subdirectories.\n"
            "2. CI Workflow Tooling: Exclude GitHub Actions (e.g. actions/setup-java, codeql-action) erroneously reported as library dependencies.\n"
            "3. Fail-Closed: If evidence is irreconcilably contradictory or ambiguous without proof, output status 'UNKNOWN'. Do NOT hallucinate.\n"
            "Output strictly valid JSON with keys: 'selected_index' (integer or null), 'status' ('VERIFIED' or 'UNKNOWN'), and 'rationale' (string)."
        )

        user_prompt = (
            f"Case: {case_id}\n"
            f"Subject: {subject}\n"
            f"Predicate: {predicate}\n"
            f"Candidates:\n{json.dumps(candidates_payload, indent=2)}\n\n"
            "Adjudicate which candidate value is the true runtime production declaration, or abstain if unresolvable:"
        )

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.0,
            "max_tokens": 4096,
        }

        try:
            resp = self.client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            if resp.status_code != 200:
                return {
                    "status": "unknown",
                    "selected_object": None,
                    "rationale": f"Gateway error HTTP {resp.status_code}: {resp.text[:100]}",
                    "evidence_locators": [],
                }
            data = resp.json()
            message = data["choices"][0]["message"]
            content = message.get("content") or ""
            reasoning = message.get("reasoning_content") or ""

            # Try to extract JSON from content, fallback to reasoning_content
            m = re.search(r"\{[^{}]*selected_index[^{}]*\}", content, re.DOTALL)
            if not m:
                m = re.search(r"\{.*\}", content, re.DOTALL)
            if not m and reasoning:
                m = re.search(r"\{[^{}]*selected_index[^{}]*\}", reasoning, re.DOTALL)
            if not m and reasoning:
                m = re.search(r"\{.*\}", reasoning, re.DOTALL)

            if m:
                decision = json.loads(m.group(0))
                idx = decision.get("selected_index")
                status = "verified" if decision.get("status") == "VERIFIED" and idx else "unknown"
                chosen_obj = candidates[idx - 1].object if idx and 1 <= idx <= len(candidates) else None
                return {
                    "status": status,
                    "selected_object": chosen_obj,
                    "rationale": decision.get("rationale", ""),
                    "evidence_locators": [e.locator for c in candidates for e in c.evidence],
                }
        except Exception as exc:
            return {
                "status": "unknown",
                "selected_object": None,
                "rationale": f"Live LLM call failed: {exc}",
                "evidence_locators": [],
            }

        return {
            "status": "unknown",
            "selected_object": None,
            "rationale": "Failed to parse structured LLM response",
            "evidence_locators": [],
        }

    def adjudicate_conflicts_batch(
        self,
        case_id: str,
        conflicts_payload: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Adjudicate a batch of conflicts in a single prompt for high throughput and coherence."""
        if not self.api_key or not conflicts_payload:
            return [{"conflict_id": item["conflict_id"], "selected_index": None, "status": "unknown", "rationale": "NETMIND_API_KEY missing or empty"} for item in conflicts_payload]

        system_prompt = (
            "You are a Principal Software Supply Chain Security Researcher (A* Tier-1 Standard).\n"
            "Your task is to adjudicate conflicting SBOM claims across multiple scanner outputs.\n"
            "Rules:\n"
            "1. Ground Truth Priority: Root project manifests and lockfiles override subdirectory examples.\n"
            "2. Canonical Identifiers: Prefer canonical ecosystem coordinates (e.g. groupId:artifactId in Maven, lowercase in PyPI, standard SPDX identifiers like Apache-2.0 over LicenseRef).\n"
            "3. Fail-Closed: If evidence is contradictory or ambiguous, output status 'UNKNOWN' and selected_index null. Do NOT hallucinate.\n"
            "Output strictly a JSON array of objects with keys: 'conflict_id' (int), 'selected_index' (int or null), 'status' ('VERIFIED' or 'UNKNOWN'), and 'rationale' (string)."
        )

        user_prompt = (
            f"Case: {case_id}\n"
            f"Adjudicate the following {len(conflicts_payload)} conflicting claims:\n"
            f"{json.dumps(conflicts_payload, indent=2)}\n\n"
            "Output strictly valid JSON array:"
        )

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.0,
            "max_tokens": 4096,
        }

        try:
            resp = self.client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            if resp.status_code != 200:
                return [{"conflict_id": item["conflict_id"], "selected_index": None, "status": "unknown", "rationale": f"HTTP {resp.status_code}"} for item in conflicts_payload]

            data = resp.json()
            message = data["choices"][0]["message"]
            content = message.get("content") or ""
            reasoning = message.get("reasoning_content") or ""

            # Extract JSON array
            m = re.search(r"\[.*\]", content, re.DOTALL)
            if not m and reasoning:
                m = re.search(r"\[.*\]", reasoning, re.DOTALL)

            if m:
                results = json.loads(m.group(0))
                return results
        except Exception as exc:
            pass

        return [{"conflict_id": item["conflict_id"], "selected_index": None, "status": "unknown", "rationale": "Adjudication parse failure"} for item in conflicts_payload]

    def resolve_ledger_live(
        self,
        input_ledger: CanonicalLedger,
        batch_size: int = 15,
    ) -> CanonicalLedger:
        """Adjudicate entire ledger with batched live LLM calls on conflicting claims."""
        out_ledger = CanonicalLedger(case_id=input_ledger.case_id)
        groups: dict[tuple[str, str], list[CanonicalClaim]] = {}
        for c in input_ledger.claims:
            groups.setdefault((c.subject, c.predicate), []).append(c)

        conflicted_items: list[tuple[tuple[str, str], list[CanonicalClaim]]] = []

        for (subj, pred), clist in groups.items():
            if pred == "depends_on":
                # Filter out CI workflow actions erroneously injected into dependency graphs
                for c in clist:
                    obj_str = str(c.object)
                    if any(k in obj_str for k in ("pkg:github/actions/", "codeql-action", "oss-fuzz", "setup-java", "setup-python")):
                        continue
                    out_ledger.add_claim(c)
                continue

            distinct_objs = {str(c.object) for c in clist}
            if len(distinct_objs) == 1:
                out_ledger.add_claim(clist[0])
            else:
                conflicted_items.append(((subj, pred), clist))

        if not conflicted_items:
            return out_ledger

        # Process conflicts in batches
        for chunk_start in range(0, len(conflicted_items), batch_size):
            chunk = conflicted_items[chunk_start : chunk_start + batch_size]
            payload_items = []
            for i, ((subj, pred), clist) in enumerate(chunk):
                payload_items.append({
                    "conflict_id": i + 1,
                    "subject": subj,
                    "predicate": pred,
                    "candidates": [
                        {
                            "candidate_index": idx + 1,
                            "value": c.object,
                            "evidence": [
                                {
                                    "source_id": e.source_id,
                                    "source_type": e.source_type,
                                    "locator": e.locator,
                                    "raw_value": str(e.raw_value)[:150],
                                }
                                for e in c.evidence
                            ],
                        }
                        for idx, c in enumerate(clist)
                    ],
                })

            decisions = self.adjudicate_conflicts_batch(input_ledger.case_id, payload_items)
            decision_map = {d.get("conflict_id"): d for d in decisions if isinstance(d, dict)}

            for i, ((subj, pred), clist) in enumerate(chunk):
                d = decision_map.get(i + 1, {"status": "unknown", "selected_index": None, "rationale": "Missing batch result"})
                status = "verified" if d.get("status") == "VERIFIED" and d.get("selected_index") is not None else "unknown"
                raw_idx = d.get("selected_index")

                # Handle 1-based index (or 0-based if emitted)
                chosen_claim = None
                if raw_idx is not None and isinstance(raw_idx, int):
                    if 1 <= raw_idx <= len(clist):
                        chosen_claim = clist[raw_idx - 1]
                    elif 0 <= raw_idx < len(clist):
                        chosen_claim = clist[raw_idx]

                if status == "verified" and chosen_claim is not None:
                    res_claim = chosen_claim.model_copy(deep=True)
                    res_claim.verification = VerificationRecord(
                        method="unverified",
                        review_status="unresolved",
                        notes=f"Live LLM ({self.model}): {d.get('rationale', '')}",
                    )
                    out_ledger.add_claim(res_claim)
                else:
                    abstained_claim = clist[0].model_copy(deep=True)
                    abstained_claim.status = "unknown"
                    abstained_claim.verification = VerificationRecord(
                        method="deterministic_parser",
                        review_status="unresolved",
                        notes=f"Live LLM ({self.model}) Abstention: {d.get('rationale', '')}",
                    )
                    out_ledger.add_claim(abstained_claim)

        return out_ledger
