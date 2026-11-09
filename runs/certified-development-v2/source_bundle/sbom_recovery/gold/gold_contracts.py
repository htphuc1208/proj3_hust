"""Versioned multi-ecosystem contracts. Legacy ledgers remain readable, never promoted."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import Field, model_validator

from sbom_recovery.core.canonical import CanonicalClaim, CanonicalLedger, StrictModel


def fingerprint(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def relative_file(value: str) -> str:
    p = PurePosixPath(value)
    if not value or p.is_absolute() or ".." in p.parts or "\\" in value:
        raise ValueError("Expected a contained relative POSIX path")
    return value


def contained(root: Path, relative: str) -> Path:
    relative_file(relative)
    root = root.resolve()
    path = root / relative
    # Reject links even if they currently point inside the root.
    if any(part.is_symlink() for part in [path, *list(path.parents)[:len(PurePosixPath(relative).parts)-1]]):
        raise ValueError("Symlinks are not evidence files")
    path.resolve().relative_to(root)
    return path


class FrozenFile(StrictModel):
    path: str
    sha256: str
    kind: Literal["manifest", "resolver", "artifact", "scanner", "source", "annotation"]

    @model_validator(mode="after")
    def valid(self):
        relative_file(self.path)
        if not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ValueError("Expected SHA-256")
        return self


class CaseManifest(StrictModel):
    schema_version: Literal["gold-case-v2"] = "gold-case-v2"
    case_id: str
    repository: str
    commit: str
    ecosystem: Literal["pypi", "maven", "npm"]
    target: str = "."
    profile: Literal["runtime_production"] = "runtime_production"
    partition: Literal["public_reference", "development", "test"] = "development"
    environment: dict[str, Any]
    evidence_cutoff: str
    source_binding: Literal["COMMIT_ONLY", "VERIFIED_RELEASE_MAPPING"] = "COMMIT_ONLY"
    release: str | None = None
    files: dict[str, FrozenFile]
    allowed_evidence: list[str]
    resolution_status: Literal["COMPLETE", "FAILED", "NOT_ATTEMPTED"] = "NOT_ATTEMPTED"
    resolution_notes: str | None = None

    @model_validator(mode="after")
    def valid(self):
        if not re.fullmatch(r"[0-9a-f]{40}", self.commit):
            raise ValueError("A full verified Git commit is required")
        relative_file(self.target)
        if not all(self.environment.get(k) for k in ("os", "arch", "runtime")):
            raise ValueError("Explicit OS, architecture and runtime required")
        if datetime.fromisoformat(self.evidence_cutoff.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("Timezone required")
        if self.source_binding == "VERIFIED_RELEASE_MAPPING" and not self.release:
            raise ValueError("Verified release mapping needs a release")
        if len(self.allowed_evidence) != len(set(self.allowed_evidence)):
            raise ValueError("Duplicate evidence ID")
        if not set(self.allowed_evidence) <= self.files.keys():
            raise ValueError("Unknown allowed evidence ID")
        for key in self.allowed_evidence:
            if self.files[key].kind == "annotation" or any(
                x.lower() in {"oracle", "gold", "annotations", "adjudication"}
                for x in PurePosixPath(self.files[key].path).parts
            ):
                raise ValueError("Oracle/annotation files cannot enter inference evidence")
        return self

    def digest(self):
        return fingerprint(self.model_dump(mode="json"))

    def verify_files(self, root: Path, evidence_ids=None):
        for key in (self.files if evidence_ids is None else evidence_ids):
            item = self.files[key]
            if hashlib.sha256(contained(root, item.path).read_bytes()).hexdigest() != item.sha256:
                raise ValueError("Changed evidence: " + item.path)


class ClaimV2(CanonicalClaim):
    target_id: str
    instance_id: str
    condition: str | None = None
    role: Literal["observation", "prediction", "gold"]
    status: Literal["verified", "verified_absent", "unknown", "not_applicable"] = "unknown"
    annotators: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def populate_claim_id(self):
        expected = fingerprint({k: getattr(self, k) for k in (
            "case_id", "target_id", "instance_id", "subject", "predicate", "object", "layer", "scope", "condition")})
        if self.claim_id and self.claim_id != expected:
            raise ValueError("Mismatched v2 claim ID")
        self.claim_id = expected
        return self

    @model_validator(mode="after")
    def gold_requires_proof(self):
        if self.role == "gold" and self.status in {"verified", "verified_absent"}:
            if not self.evidence or any(not re.fullmatch(r"[0-9a-f]{64}", e.artifact_sha256 or "")
                                        or e.source_type == "scanner_sbom" for e in self.evidence):
                raise ValueError("Gold requires independently bound evidence, never scanner votes")
            if self.verification.method == "unverified" or self.verification.review_status != "accepted":
                raise ValueError("Gold requires accepted verification")
            if self.verification.method == "dual_annotator_adjudication" and len(set(self.annotators)) < 2:
                raise ValueError("Two independent annotators required")
            if self.status == "verified_absent" and not self.verification.notes:
                raise ValueError("Negative gold needs an explicit bounded search scope")
        return self


class LedgerV2(CanonicalLedger):
    schema_version: Literal["canonical-ledger-v2"] = "canonical-ledger-v2"
    case_manifest_sha256: str
    role: Literal["observation", "prediction", "gold"]
    claims: list[ClaimV2] = Field(default_factory=list)

    @model_validator(mode="after")
    def bound(self):
        if not re.fullmatch(r"[0-9a-f]{64}", self.case_manifest_sha256):
            raise ValueError("Case binding required")
        if any(c.case_id != self.case_id or c.role != self.role for c in self.claims):
            raise ValueError("Case/role mismatch")
        return self

    def add_claim(self, claim):
        if not isinstance(claim, ClaimV2) or claim.role != self.role:
            raise ValueError("Cannot insert legacy or differently classified claims")
        super().add_claim(claim)

    def find_conflicts(self):
        groups = {}
        for c in self.claims:
            if c.predicate == "depends_on": continue
            key = (c.target_id,c.instance_id,c.subject,c.predicate,c.layer,c.scope,c.condition)
            groups.setdefault(key,[]).append(c)
        return {k:cs for k,cs in groups.items() if len({fingerprint(c.object) for c in cs})>1}


def read_ledger(path):
    data = json.loads(Path(path).read_text())
    return (LedgerV2 if data.get("schema_version") == "canonical-ledger-v2" else CanonicalLedger).model_validate(data)
