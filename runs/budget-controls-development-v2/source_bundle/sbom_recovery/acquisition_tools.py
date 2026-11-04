"""Evidence Acquisition Tools and Budgeted Schedulers (Experiment E2).

Provides controlled, budgeted access to evidence sources:
- inspect_manifest
- read_lockfile
- read_artifact_metadata
- check_artifact_hash

Implements 3 comparative schedulers:
- D1: Fixed-Order (Static source priority)
- D2: Deterministic Greedy (Information-gain ranking on unresolved conflicts)
- A2: Agent Planner (Dynamic contextual tool planning)
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Literal
from pydantic import BaseModel, ConfigDict, Field

from .canonical import (
    CanonicalClaim,
    CanonicalLedger,
    EvidenceItem,
    VerificationRecord,
)


class ToolActionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tool_name: str
    arguments: dict[str, Any]
    bytes_returned: int
    success: bool
    details: str


class EvidenceToolCatalog:
    """Reads only a frozen allowlist; oracle paths and symlinks are never eligible."""

    TOOLS = {"inspect_manifest", "read_lockfile", "read_artifact_metadata", "check_artifact_hash"}
    DENIED = {"oracle", "gold", "annotations", "adjudication", "ground_truth"}
    DEFAULT_NAMES = {"pyproject.toml", "setup.cfg", "requirements.txt", "package.json",
                     "package-lock.json", "uv.lock", "poetry.lock", "pom.xml", "METADATA"}

    def __init__(self, target_dir=None, byte_limit_per_action=65536, allowed_files=None, expected_hashes=None):
        self.target_dir = Path(target_dir).resolve() if target_dir else None
        if byte_limit_per_action < 0:
            raise ValueError("Negative byte limit")
        self.byte_limit_per_action = byte_limit_per_action
        # Default is a small compatibility catalog, never a recursive filesystem listing.
        self.allowed_files = dict(allowed_files) if allowed_files is not None else {
            name: name for name in self.DEFAULT_NAMES if self.target_dir and (self.target_dir / name).is_file()}
        self.expected_hashes = dict(expected_hashes or {})
        from .gold_contracts import contained
        for key, relative in self.allowed_files.items():
            if key in self.expected_hashes or any(part.lower() in self.DENIED for part in Path(relative).parts):
                continue
            try:
                path = contained(self.target_dir, relative)
                with path.open("rb") as stream:
                    self.expected_hashes[key] = hashlib.file_digest(stream, "sha256").hexdigest()
            except (ValueError, OSError, AttributeError):
                continue

    @classmethod
    def from_case(cls, case_path, byte_limit_per_action=65536):
        from .gold_contracts import CaseManifest
        case = CaseManifest.model_validate_json(Path(case_path).read_text())
        return cls(Path(case_path).resolve().parent, byte_limit_per_action,
                   {key:case.files[key].path for key in case.allowed_evidence},
                   {key:case.files[key].sha256 for key in case.allowed_evidence})

    def _read(self, evidence_id, max_bytes=None):
        from .gold_contracts import contained
        if not self.target_dir or evidence_id not in self.allowed_files:
            return {"error": "Evidence ID not allowed"}, 0
        relative = self.allowed_files[evidence_id]
        if any(part.lower() in self.DENIED for part in Path(relative).parts):
            return {"error": "Oracle/annotation evidence denied"}, 0
        try:
            p = contained(self.target_dir, relative)
            limit = min(self.byte_limit_per_action, max_bytes if max_bytes is not None else self.byte_limit_per_action)
            if limit < 0:
                raise ValueError("Negative byte limit")
            with p.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != self.expected_hashes.get(evidence_id):
                    return {"error": "Frozen evidence digest changed"}, 0
                stream.seek(0)
                raw = stream.read(limit)
            return {"content": raw.decode("utf-8", errors="replace"),
                    "sha256": hashlib.sha256(raw).hexdigest(), "hash_scope": "returned_bytes",
                    "truncated": p.stat().st_size > len(raw)}, len(raw)
        except (ValueError, OSError):
            return {"error": "Evidence unavailable or unsafe"}, 0

    def inspect_manifest(self, manifest_file, max_bytes=None):
        return self._read(manifest_file, max_bytes)

    def read_lockfile(self, lockfile_name, max_bytes=None):
        return self._read(lockfile_name, max_bytes)

    def read_artifact_metadata(self, artifact_path, max_bytes=None):
        return self._read(artifact_path, max_bytes)

    def check_artifact_hash(self, artifact_path, max_bytes=None):
        result, size = self._read(artifact_path, max_bytes)
        if "error" not in result and result["truncated"]:
            return {"error": "Full artifact hash unavailable within budget"}, size
        result.pop("content", None)
        return result, size


class BudgetedScheduler:
    """Every attempted action is charged; output cannot exceed remaining bytes."""

    def __init__(self, catalog, max_actions=5, max_bytes=262144):
        if max_actions < 0 or max_bytes < 0:
            raise ValueError("Negative budget")
        self.catalog, self.max_actions, self.max_bytes = catalog, max_actions, max_bytes
        self.actions_used = self.bytes_used = 0
        self.history = []

    def can_act(self):
        return self.actions_used < self.max_actions and self.bytes_used < self.max_bytes

    def execute_action(self, tool_name, **kwargs):
        if not self.can_act():
            return {"error": "Budget exhausted"}
        self.actions_used += 1
        remaining = self.max_bytes - self.bytes_used
        if tool_name not in EvidenceToolCatalog.TOOLS or "max_bytes" in kwargs:
            result, size = {"error": "Unknown tool or reserved argument"}, 0
        else:
            try:
                result, size = getattr(self.catalog, tool_name)(**kwargs, max_bytes=remaining)
                if not isinstance(size, int) or not 0 <= size <= remaining:
                    result, size = {"error": "Tool violated output budget"}, 0
            except (TypeError, ValueError, OSError):
                result, size = {"error": "Invalid action or unavailable evidence"}, 0
        self.bytes_used += size
        self.history.append(ToolActionRecord(tool_name=tool_name, arguments=kwargs, bytes_returned=size,
                                            success="error" not in result, details=result.get("error", "OK")))
        return result


class DeterministicSchedulers:
    """Pre-registered deterministic baselines D1 (Fixed-Order) and D2 (Greedy Information-Gain)."""

    @classmethod
    def run_d1_fixed_order(
        cls,
        scheduler: BudgetedScheduler,
        manifest_files: list[str],
        lockfiles: list[str],
    ) -> list[ToolActionRecord]:
        """D1: Fixed sequence: lockfiles first, then manifests."""
        # Step 1: Probe lockfiles
        for lf in lockfiles:
            if not scheduler.can_act():
                break
            scheduler.execute_action("read_lockfile", lockfile_name=lf)

        # Step 2: Probe manifests
        for mf in manifest_files:
            if not scheduler.can_act():
                break
            scheduler.execute_action("inspect_manifest", manifest_file=mf)

        return scheduler.history

    @classmethod
    def run_d2_greedy(
        cls,
        scheduler: BudgetedScheduler,
        unresolved_conflicts: list[tuple[str, str]],
        available_files: list[str],
    ) -> list[ToolActionRecord]:
        """D2: Greedy information-gain: probes sources matching conflicted package names."""
        # Score files by number of matching conflicted subjects
        file_scores: list[tuple[int, str]] = []
        for f in available_files:
            score = 0
            for subj, _ in unresolved_conflicts:
                pkg_name = subj.split("/")[-1].split("@")[0]
                if pkg_name.lower() in f.lower():
                    score += 1
            if "lock" in f:
                score += 5  # Lockfiles have high expected information yield
            file_scores.append((score, f))

        file_scores.sort(key=lambda x: x[0], reverse=True)

        for _, f in file_scores:
            if not scheduler.can_act():
                break
            if "lock" in f:
                scheduler.execute_action("read_lockfile", lockfile_name=f)
            else:
                scheduler.execute_action("inspect_manifest", manifest_file=f)

        return scheduler.history


class AgentPlanner:
    """Legacy deterministic heuristic, NOT an LLM planning arm.
    
    Plans next evidence action by targeting high-centrality root artifacts first,
    then probing specific conflicted packages, stopping early when resolved.
    """

    @classmethod
    def run_a2_planner(
        cls,
        scheduler: BudgetedScheduler,
        unresolved_conflicts: list[tuple[str, str]],
        available_files: list[str],
    ) -> list[ToolActionRecord]:
        visited: set[str] = set()

        while scheduler.can_act():
            chosen_file: str | None = None
            tool_name: str | None = None

            # Phase 1: Acquire root lockfile first to establish authoritative runtime baseline
            root_lockfiles = [
                f for f in available_files
                if f not in visited and any(k in f.lower() for k in ("uv.lock", "package-lock.json", "poetry.lock", "pom.xml", "build.gradle"))
            ]
            if root_lockfiles:
                chosen_file = root_lockfiles[0]
                tool_name = "read_lockfile"
            else:
                # Phase 2: Root manifest
                root_manifests = [
                    f for f in available_files
                    if f not in visited and any(k in f.lower() for k in ("pyproject.toml", "package.json", "setup.cfg"))
                ]
                if root_manifests:
                    chosen_file = root_manifests[0]
                    tool_name = "inspect_manifest"
                else:
                    # Phase 3: Targeted conflict probing
                    best_cand = None
                    best_score = -1
                    for f in available_files:
                        if f in visited:
                            continue
                        score = sum(1 for s, _ in unresolved_conflicts if s.split("/")[-1].split("@")[0].lower() in f.lower())
                        if score > best_score:
                            best_score = score
                            best_cand = f

                    if best_cand and best_score > 0:
                        chosen_file = best_cand
                        tool_name = "read_artifact_metadata" if "metadata" in best_cand.lower() else "inspect_manifest"
                    else:
                        # No informative actions remain -> stop early (budget conservation)
                        break

            if not chosen_file or not tool_name:
                break

            visited.add(chosen_file)
            if tool_name == "read_lockfile":
                scheduler.execute_action("read_lockfile", lockfile_name=chosen_file)
            elif tool_name == "read_artifact_metadata":
                scheduler.execute_action("read_artifact_metadata", artifact_path=chosen_file)
            else:
                scheduler.execute_action("inspect_manifest", manifest_file=chosen_file)

        return scheduler.history
