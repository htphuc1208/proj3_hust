#!/usr/bin/env python3
"""Offline Public Registry Evidence Provider.

Maintains a frozen offline snapshot of public package distribution metadata
(wheel Requires-Dist and release records). Strictly isolated from ground-truth
oracles (pip_inspect.json, pip_install_report.json, and host venvs).
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


class SecurityIsolationViolation(Exception):
    """Raised when an evidence provider attempts to access oracle or target ground truth."""
    pass


class FrozenRegistryEvidenceProvider:
    """Provides public distribution requirement evidence strictly from a frozen snapshot."""

    def __init__(self, snapshot_dir: Path, manifest_path: Optional[Path] = None):
        self.snapshot_dir = Path(snapshot_dir)
        self.manifest_path = Path(manifest_path) if manifest_path else self.snapshot_dir / "evidence_manifest.json"
        self.source_name = "frozen-public-registry-snapshot"
        self.packages: Dict[str, Dict[str, Any]] = {}
        self.manifest: Dict[str, Any] = {}
        self._load_snapshot()

    def _assert_isolation(self, path: Path):
        path_str = str(path.resolve())
        forbidden_patterns = ["pip_inspect", "pip_install_report", "ground_truth", ".venv", "runs/"]
        for forbidden in forbidden_patterns:
            if forbidden in path_str and "evidence_snapshot" not in path_str:
                raise SecurityIsolationViolation(
                    f"Label Leakage Alert: Evidence provider is forbidden from accessing target artifact: {path_str}"
                )

    def _load_snapshot(self):
        self._assert_isolation(self.snapshot_dir)
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Evidence manifest not found at: {self.manifest_path}")

        self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        for entry in self.manifest.get("artifacts", []):
            pkg_name = canonicalize_name(entry["name"])
            version = entry["version"]
            meta_file = self.snapshot_dir / entry["metadata_file"]
            if meta_file.resolve().parent != self.snapshot_dir.resolve():
                raise SecurityIsolationViolation("Metadata file escapes the frozen snapshot root")
            self._assert_isolation(meta_file)

            if meta_file.exists():
                data = json.loads(meta_file.read_text(encoding="utf-8"))
                # Verify SHA-256 integrity
                file_hash = hashlib.sha256(meta_file.read_bytes()).hexdigest()
                if entry.get("sha256") and file_hash != entry["sha256"]:
                    raise ValueError(f"Integrity check failed for snapshot artifact: {meta_file.name}")
                self.packages[f"{pkg_name}@{version}"] = data

    def get_requirements(self, purl: str) -> Optional[List[Any]]:
        """
        Returns the declared requirement strings for a package PURL.
        Returns None if package/version is not in public snapshot (EVIDENCE_UNAVAILABLE).
        """
        prefix = "pkg:pypi/"
        if not purl.startswith(prefix) or "@" not in purl:
            return None
        raw_name, version = purl[len(prefix):].split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)
        pkg_name = canonicalize_name(raw_name)
        key = f"{pkg_name}@{version}"

        if key not in self.packages:
            # Epistemic honesty: do not invent, report missing evidence
            return None

        artifact_data = self.packages[key]
        status = artifact_data.get("metadata_status")
        if status in ("UNAVAILABLE", "INCOMPLETE", "DYNAMIC_UNRESOLVED", "INCOMPATIBLE", "FUTURE_ARTIFACT"):
            return None
        # Legacy fallback records with no verified distribution bytes do not prove
        # that an empty release-level requires_dist is a complete dependency list.
        provenance = artifact_data.get("provenance", {})
        if provenance.get("verification_status") == "RELEASE_METADATA_FALLBACK":
            return None
        raw_reqs = artifact_data.get("requires_dist", []) or []

        # Convert to DependencyRequirement objects expected by resolver.py
        from sbom_recovery.core.resolver import DependencyRequirement
        results = []
        for raw in raw_reqs:
            try:
                r = Requirement(raw)
                target_purl = f"pkg:pypi/{canonicalize_name(r.name)}"
                # If target has pinned specifier, extract conservative lower bound or exact version
                marker_str = str(r.marker) if r.marker else None
                specifier_str = str(r.specifier) if r.specifier else None
                results.append(DependencyRequirement(
                    target_purl=target_purl,
                    marker=marker_str,
                    extra=None,
                    specifier=specifier_str,
                    requested_extras=set(r.extras)
                ))
            except Exception:
                return None  # Partial parsing must not masquerade as complete requirements.
        return results


def build_evidence_snapshot(packages_metadata: Dict[str, Dict[str, Any]], output_dir: Path, source_url="https://pypi.org/pypi") -> Path:
    """Utility to build and freeze a deterministic offline evidence snapshot."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": "evidence-snapshot-v1",
        "frozen_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": source_url,
        "policy": "artifact-level distribution wheel metadata, blinded to target ground-truth",
        "artifacts": []
    }

    for key, meta in sorted(packages_metadata.items()):
        name, version = key.split("@", 1)
        canonical = canonicalize_name(name)
        filename = f"{canonical}-{version}.json"
        filepath = out / filename
        data = {
            "name": canonical,
            "version": version,
            "distribution_type": meta.get("distribution_type", "wheel"),
            "requires_dist": meta.get("requires_dist", []),
            "source_artifact": meta.get("source_artifact", f"{canonical}-{version}-py3-none-any.whl"),
        }
        content = json.dumps(data, indent=2, sort_keys=True) + "\n"
        filepath.write_text(content, encoding="utf-8")
        file_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()

        manifest["artifacts"].append({
            "name": canonical,
            "version": version,
            "metadata_file": filename,
            "sha256": file_sha256,
            "origin_url": f"{source_url}/{canonical}/{version}/json"
        })

    manifest_file = out / "evidence_manifest.json"
    manifest_file.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_file
