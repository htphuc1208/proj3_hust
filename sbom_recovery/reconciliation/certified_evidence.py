"""Target-bound, location-checked evidence, shared as an explicit trusted base.

Neither oracle labels nor a public registry can confer target authority here.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from sbom_recovery.core.formats import NativeDocument, package_purl, sha
from sbom_recovery.gold.gold_contracts import contained
from sbom_recovery.campaign.targets import metadata_inventory
from .contracts_v2 import EvidenceManifestV2, EvidenceSourceV2, occurrence_id, timestamp


@dataclass
class Distribution:
    occurrence: str
    path: str
    name: str
    version: str
    source_id: str
    requirements: list[tuple[int, str, Requirement]]
    complete: bool


def locations(document):
    """Only explicit native file locations; no substring/suffix/PURL guessing."""
    native = NativeDocument(document)
    result = defaultdict(set)
    if native.format == "spdx":
        files = {f.get("SPDXID"): f.get("fileName") for f in document.get("files", [])}
        for r in document.get("relationships", []):
            if r.get("relationshipType") == "CONTAINS" and files.get(r.get("relatedSpdxElement")):
                result[r.get("spdxElementId")].add(files[r["relatedSpdxElement"]].lstrip("/"))
        # Syft's native SPDX uses this explicit provenance field rather than
        # package-to-METADATA CONTAINS relationships. Recognize the whole known
        # template; never search arbitrary prose for a convenient path suffix.
        prefix = "acquired package info from installed python package manifest file: "
        for ref, item in native.packages().items():
            source_info = item.get("sourceInfo", "")
            if source_info.startswith(prefix):
                for value in source_info[len(prefix):].split(", "):
                    if value.endswith(".dist-info/METADATA"):
                        result[ref].add(value.lstrip("/"))
    else:
        for ref, item in native.packages().items():
            for prop in item.get("properties", []):
                if (prop.get("name") == "sbom-recovery:metadata-path"
                        or re.fullmatch(r"syft:location:[0-9]+:path", prop.get("name", ""))):
                    value = prop.get("value")
                    if isinstance(value, str):
                        result[ref].add(value.lstrip("/"))
    return result


def in_scope(path, context):
    p = PurePosixPath(path)
    return (p.name == "METADATA" and p.parent.name.endswith(".dist-info")
            and p.parent.parent.as_posix() == context.installation_scope)


def parse_distribution(source, raw, target_id):
    msg = BytesParser().parsebytes(raw)
    if (msg.defects or len(msg.get_all("Name", [])) != 1 or len(msg.get_all("Version", [])) != 1
            or len(msg.get_all("Metadata-Version", [])) != 1):
        raise ValueError("INVALID_METADATA_IDENTITY")
    name, version = canonicalize_name(msg["Name"]), msg["Version"]
    if msg["Metadata-Version"].split(".")[0] not in {"1", "2"}:
        raise ValueError("UNSUPPORTED_METADATA_MAJOR_VERSION")
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        raise ValueError("INVALID_METADATA_NAME")
    Version(version)
    # Unknown future versions cannot justify negative evidence. Dynamic in an
    # installed distribution is informational (PyPA Core Metadata), unlike sdist.
    complete = (msg["Metadata-Version"] in {"1.2", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6"}
                and not msg.get_all("Requires", []))
    requirements = []
    for index, text in enumerate(msg.get_all("Requires-Dist", [])):
        try:
            requirements.append((index, text, Requirement(text)))
        except InvalidRequirement:
            complete = False
    return Distribution(occurrence_id(target_id, source.occurrence_path), source.occurrence_path,
                        name, version, source.source_id, requirements, complete)


class EvidenceView:
    def __init__(self, document, context, manifest, acquired):
        self.manifest = EvidenceManifestV2.model_validate(
            manifest.model_dump() if isinstance(manifest, EvidenceManifestV2) else manifest)
        manifest = self.manifest
        if manifest.target_id != context.target_id or manifest.observation_sha256 != sha(document):
            raise ValueError("Evidence target/observation mismatch")
        native = NativeDocument(document)
        if native.issues():
            raise ValueError("Ambiguous or dangling native references")
        self.distributions, self.conflicts, self.diagnostics = {}, set(), []
        self.by_source, self.inventory = {}, set()
        grouped = defaultdict(list)
        expected = {s.source_id for s in manifest.sources if s.acquired}
        if set(acquired) != expected:
            raise ValueError("Acquired sources differ from the frozen evidence manifest")
        occurrence_hashes = defaultdict(set)
        for source in manifest.sources:
            if source.kind != "installed_metadata":
                self.diagnostics.append({"source_id": source.source_id, "reason": "NON_TARGET_AUTHORITY"})
                # Public metadata is retained but cannot certify target relations.
            elif in_scope(source.occurrence_path, context):
                key = occurrence_id(context.target_id, source.occurrence_path)
                self.inventory.add(key)
                occurrence_hashes[key].add(source.sha256)
            else:
                self.diagnostics.append({"source_id": source.source_id, "reason": "OUTSIDE_INSTALLATION_SCOPE"})
            if not source.acquired:
                continue
            raw = acquired[source.source_id]
            if (len(raw) != source.bytes or hashlib.sha256(raw).hexdigest() != source.sha256
                    or timestamp(source.available_at) > timestamp(context.evidence_cutoff)):
                raise ValueError("Evidence bytes/size/availability mismatch")
            if source.kind != "installed_metadata" or not in_scope(source.occurrence_path, context):
                continue
            key = occurrence_id(context.target_id, source.occurrence_path)
            try:
                item = parse_distribution(source, raw, context.target_id)
                self.by_source[source.source_id] = item
                grouped[key].append(item)
            except (ValueError, InvalidVersion) as exc:
                self.diagnostics.append({"source_id": source.source_id, "reason": str(exc)})
        self.conflicts.update(k for k, values in occurrence_hashes.items() if len(values) > 1)
        for key, items in grouped.items():
            if len(items) != 1 or key in self.conflicts:
                self.conflicts.add(key)
                self.diagnostics.append({"occurrence_id": key, "reason": "CONFLICTING_OCCURRENCE_EVIDENCE"})
            else:
                self.distributions[key] = items[0]
        self.by_name = defaultdict(list)
        for key, item in self.distributions.items():
            self.by_name[item.name].append(key)
        self.bound, self.binding_conflicts = {}, set()
        paths, packages = locations(document), native.packages()
        counts = Counter(manifest.bindings.values())
        for ref, key in manifest.bindings.items():
            if key in self.conflicts:
                self.binding_conflicts.add(ref)
                continue
            item, record = self.distributions.get(key), packages.get(ref)
            if item is None or record is None or counts[key] != 1:
                continue
            if item.path not in paths[ref]:
                self.diagnostics.append({"ref": ref, "reason": "OCCURRENCE_LOCATION_UNBOUND"})
                continue
            purl = package_purl(record, native.format)
            if purl != f"pkg:pypi/{item.name}@{item.version}":
                self.binding_conflicts.add(ref)
                continue
            self.bound[ref] = key
        self.reverse = {key: ref for ref, key in self.bound.items()}

    def matching_children(self, requirement):
        if requirement.url:
            return []
        return [key for key in self.by_name[canonicalize_name(requirement.name)]
                if requirement.specifier.contains(self.distributions[key].version, prereleases=True)]

    def complete_inventory(self):
        return (self.complete_identities()
                and all(d.complete for d in self.distributions.values()))

    def complete_identities(self):
        sources = [s for s in self.manifest.sources if s.kind == "installed_metadata"
                   and occurrence_id(self.manifest.target_id, s.occurrence_path) in self.inventory]
        return (self.manifest.inventory_complete and not self.conflicts and all(s.acquired for s in sources)
                and len(sources) == len(self.inventory)
                and self.inventory == self.distributions.keys())

    def unique_child(self, requirement):
        matches = self.matching_children(requirement)
        # An unread occurrence could have the same Name and a compatible Version.
        return matches[0] if self.complete_identities() and len(matches) == 1 else None


def read_bundle(path):
    path = Path(path)
    manifest = EvidenceManifestV2.model_validate_json(path.read_text())
    acquired = {s.source_id: contained(path.parent, s.path).read_bytes()
                for s in manifest.sources if s.acquired}
    return manifest, acquired


def collect_evidence(document, context, target, available_at, destination):
    """Trusted collector. Copy only top-level METADATA, never reference files.

    inventory_complete asserts enumeration of metadata in this directory, not
    integrity of installed executable contents or historical deployment identity.
    """
    target, destination = Path(target).resolve(strict=True), Path(destination)
    paths, binding = metadata_inventory(target)
    if binding != context.target_id:
        raise ValueError("Target metadata digest does not match declared context")
    if timestamp(available_at) > timestamp(context.evidence_cutoff):
        raise ValueError("Evidence is after cutoff")
    sources, acquired, bindings = [], {}, {}
    observed_locations = locations(document)
    for path in paths:
        relative = path.relative_to(target).as_posix()
        if not in_scope(relative, context):
            continue
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        sid = sha(["installed_metadata", context.target_id, relative, digest])
        source = EvidenceSourceV2(source_id=sid, path=f"sources/{sid}.metadata", occurrence_path=relative,
                                  sha256=digest, bytes=len(raw), available_at=available_at)
        sources.append(source)
        acquired[sid] = raw
        for ref, observed_paths in observed_locations.items():
            if relative in observed_paths:
                key = occurrence_id(binding, relative)
                if ref in bindings and bindings[ref] != key:
                    # Multiple physical occurrences cannot be silently collapsed.
                    bindings[ref] = "AMBIGUOUS"
                else:
                    bindings[ref] = key
    if metadata_inventory(target)[1] != binding:
        raise ValueError("Target changed during evidence collection")
    manifest = EvidenceManifestV2(target_id=binding, observation_sha256=sha(document),
                                  inventory_complete=True, sources=sources,
                                  bindings={r: k for r, k in bindings.items() if k != "AMBIGUOUS"})
    EvidenceView(document, context, manifest, acquired)
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "sources").mkdir()
    for source in sources:
        (destination / source.path).write_bytes(acquired[source.source_id])
    (destination / "manifest.json").write_text(manifest.model_dump_json(indent=2) + "\n")
    return manifest
