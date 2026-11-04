"""Content-addressed evidence and deterministic extraction; model text is never a fact."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import tomllib

from packaging.requirements import Requirement, InvalidRequirement
from packaging.utils import canonicalize_name
from packaging.version import Version, InvalidVersion

from .contracts import EvidenceRecord, TargetContext
from .formats import NativeDocument, encoded, package_purl, sha
from .scope import installed_candidates
from .storage import save_bytes, quarantine


def utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def marker_value(requirement, context, extras):
    if not requirement.marker:
        return True
    if context is None:
        return None
    text = str(requirement.marker)
    unknown = {"platform_release", "platform_version", "implementation_version", "platform_python_implementation"}
    if any(re.search(r"\b" + key + r"\b", text) for key in unknown):
        return None
    env = {k: getattr(context, k) for k in ("os_name", "sys_platform", "platform_machine", "python_version",
                                           "python_full_version", "platform_system")}
    env["implementation_name"] = "cpython"
    return any(requirement.marker.evaluate({**env, "extra": extra}) for extra in (set(extras) | {""}))


class EvidenceStore:
    """The trusted controller owns this store; tools expose IDs, never paths or SQL."""
    def __init__(self, root):
        self.root = Path(root).resolve()
        (self.root / "blobs").mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.root / "index.sqlite")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, record TEXT NOT NULL)")
        self.db.commit()

    def close(self):
        self.db.close()

    def add(self, content, *, source, kind, available_at=None, target_id=None, authority="SUPPORTED", availability_kind=None):
        # This is a collector API, deliberately absent from the model tool allowlist.
        raw = content if isinstance(content, bytes) else encoded(content)
        digest = hashlib.sha256(raw).hexdigest()
        record = EvidenceRecord(evidence_id="", sha256=digest, source=source, acquired_at=utc(), kind=kind,
                                available_at=available_at, target_id=target_id, authority=authority,
                                availability_kind=availability_kind or ("OBSERVED_TIME" if available_at else "UNKNOWN"))
        identity = record.model_dump(exclude={"acquired_at", "evidence_id"})
        record.evidence_id = sha(identity)
        path = self.root / "blobs" / digest
        if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            quarantine(path)
        if not path.exists():
            save_bytes(path, raw)
        self.db.execute("INSERT OR IGNORE INTO evidence VALUES (?,?)", (record.evidence_id, record.model_dump_json()))
        self.db.commit()
        return record.evidence_id

    def records(self):
        return [EvidenceRecord.model_validate_json(row[0]) for row in self.db.execute("SELECT record FROM evidence ORDER BY id")]

    def read(self, evidence_id):
        if not re.fullmatch(r"[0-9a-f]{64}", evidence_id):
            raise ValueError("Invalid evidence ID")
        row = self.db.execute("SELECT record FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown evidence ID")
        record = EvidenceRecord.model_validate_json(row[0])
        recorded = json.loads(row[0])
        identity = {k: v for k, v in recorded.items() if k not in {"acquired_at", "evidence_id"}}
        if sha(identity) != evidence_id:
            raise ValueError("EVIDENCE_MANIFEST_DIGEST_MISMATCH")
        if record.evidence_id != evidence_id or not re.fullmatch(r"[0-9a-f]{64}", record.sha256):
            raise ValueError("Invalid evidence manifest")
        raw = (self.root / "blobs" / record.sha256).read_bytes()
        if hashlib.sha256(raw).hexdigest() != record.sha256:
            raise ValueError("EVIDENCE_DIGEST_MISMATCH")
        return record, raw

    def manifest(self):
        return {"schema_version": "evidence-manifest-v1", "records": [json.loads(row[0]) for row in
                 self.db.execute("SELECT record FROM evidence ORDER BY id")]}

    def import_record(self, payload, raw):
        record = EvidenceRecord.model_validate(payload)
        identity = {k: v for k, v in payload.items() if k not in {"acquired_at", "evidence_id"}}
        if sha(identity) != record.evidence_id or hashlib.sha256(raw).hexdigest() != record.sha256:
            raise ValueError("Imported evidence failed digest binding")
        path = self.root / "blobs" / record.sha256
        if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() != record.sha256:
            quarantine(path)
        if not path.exists():
            save_bytes(path, raw)
        self.db.execute("INSERT OR IGNORE INTO evidence VALUES (?,?)", (record.evidence_id, json.dumps(payload)))
        self.db.commit()

    def export(self, destination):
        out = EvidenceStore(destination)
        try:
            for payload in self.manifest()["records"]:
                _, raw = self.read(payload["evidence_id"])
                out.import_record(payload, raw)
        finally:
            out.close()

    def claims(self, document, context):
        """Derive a finite set of inspectable claims, without oracle labels or B3 membership."""
        self.last_diagnostics = []
        native = NativeDocument(document)
        items, _ = installed_candidates(document)
        # Missing identity fields remain repairable if the record is not explicitly another inventory kind.
        for ref, item in native.packages().items():
            origin = item.get("sourceInfo", "")
            if not package_purl(item, native.format) and item.get("name") and not any(k in origin for k in ("/_vendor/", "/vendored/", "/tests/data/")):
                items[ref] = item
        by_name, by_purl = {}, {}
        for ref, item in items.items():
            by_name.setdefault(canonicalize_name(item.get("name", "")), []).append(ref)
            purl = package_purl(item, native.format)
            if purl:
                by_purl.setdefault(purl, []).append(ref)
        claims, metadata = [], []
        for r in self.records():
            r, raw = self.read(r.evidence_id)
            authority = r.authority
            if context is None or r.target_id != context.target_id:
                authority = "SUPPORTED"
            if r.available_at and context:
                if datetime.fromisoformat(r.available_at.replace("Z", "+00:00")) > datetime.fromisoformat(context.evidence_cutoff.replace("Z", "+00:00")):
                    continue
            def emit(operation, subject, value, field=None, **details):
                claims.append({"operation": operation, "subject": subject, "field": field, "value": deepcopy(value),
                               "evidence_ids": [r.evidence_id], "authority": authority, **details})
            if r.kind == "target_metadata":
                msg = BytesParser().parsebytes(raw)
                if not msg.get("Name") or not msg.get("Version"):
                    continue
                name, version = canonicalize_name(msg["Name"]), msg["Version"]
                purl = f"pkg:pypi/{name}@{version}"
                matches = by_name.get(name, [])
                if len(matches) > 1:
                    continue  # A name alone does not identify an installed occurrence.
                ref = matches[0] if matches else ("SPDXRef-" if native.format == "spdx" else "recovered-") + sha([r.source, purl])[:24]
                component = {"name": name, native.id_field: ref}
                if native.format == "spdx":
                    component.update(versionInfo=version, downloadLocation="NOASSERTION", filesAnalyzed=False,
                        externalRefs=[{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}])
                else:
                    component.update(type="library", version=version, purl=purl)
                if matches:
                    current = items[ref]
                    if canonicalize_name(current.get("name", "")) == name:
                        component["name"] = current["name"]
                    existing_purl = package_purl(current, native.format)
                    from packageurl import PackageURL
                    if existing_purl:
                        parsed = PackageURL.from_string(existing_purl)
                        if parsed.name == name and parsed.version == version:
                            purl = existing_purl  # Metadata alone cannot erase qualifiers or subpaths.
                    if native.format == "spdx":
                        preserved = [deepcopy(x) for x in current.get("externalRefs", []) if x.get("referenceType") != "purl"]
                        preserved.append({"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl})
                        component["externalRefs"] = preserved
                    else:
                        component["purl"] = purl
                if not matches:
                    emit("add_component", ref, component)
                for key, value in component.items():
                    if key not in {native.id_field, "type", "downloadLocation", "filesAnalyzed"}:
                        emit("set_field", ref, value, key)
                if msg.get("License-Expression"):
                    field = "licenseDeclared" if native.format == "spdx" else "licenses"
                    value = msg["License-Expression"] if native.format == "spdx" else [{"expression": msg["License-Expression"]}]
                    emit("set_field", ref, value, field)
                metadata.append({"ref": ref, "purl": purl, "name": name, "version": version,
                                 "requirements": msg.get_all("Requires-Dist", []), "evidence_id": r.evidence_id,
                                 "authority": authority})
            elif r.kind == "peer_sbom":
                peer = NativeDocument(json.loads(raw))
                if peer.format != native.format:
                    continue
                pcounts = {}
                for ref, item in peer.packages().items():
                    p = package_purl(item, peer.format)
                    pcounts.setdefault(p, []).append((ref, item))
                for purl, rows in pcounts.items():
                    if not purl or len(rows) != 1 or len(by_purl.get(purl, [])) != 1:
                        continue
                    ref = by_purl[purl][0]
                    for field, value in rows[0][1].items():
                        if field != native.id_field:
                            emit("set_field", ref, value, field)
            elif r.kind == "registry":
                payload = json.loads(raw)
                purl, info = payload["purl"], payload["info"]
                if len(by_purl.get(purl, [])) != 1:
                    continue
                ref = by_purl[purl][0]
                # A registry hash is not a target-file checksum. Do not emit one.
                if info.get("license_expression"):
                    field = "licenseDeclared" if native.format == "spdx" else "licenses"
                    value = info["license_expression"] if native.format == "spdx" else [{"expression": info["license_expression"]}]
                    emit("set_field", ref, value, field)
                metadata.append({"ref": ref, "purl": purl, "name": canonicalize_name(info["name"]),
                    "version": info["version"], "requirements": info.get("requires_dist"),
                    "evidence_id": r.evidence_id, "authority": "SUPPORTED"})
            elif r.kind == "source_file" and context:
                # Parse declarations, never execute setup.py or resolve context-free versions.
                requirements = None
                source_name = r.source.rsplit("/", 1)[-1].removeprefix("source:")
                if source_name == "pyproject.toml":
                    try:
                        project = tomllib.loads(raw.decode())["project"]
                        requirements = project.get("dependencies")
                        project_name = canonicalize_name(project.get("name", ""))
                        for extra in context.active_extras:
                            if requirements is not None:
                                requirements = requirements + project.get("optional-dependencies", {}).get(extra, [])
                    except (ValueError, KeyError, UnicodeError, TypeError):
                        requirements, project_name = None, ""
                elif source_name.startswith("requirements") and source_name.endswith(".txt"):
                    lines = raw.decode(errors="replace").splitlines()
                    if any(line.lstrip().startswith("-") or line.rstrip().endswith("\\") for line in lines):
                        self.last_diagnostics.append({"source": r.source, "reason": "UNSUPPORTED_REQUIREMENTS_DIRECTIVE", "status": "UNKNOWN"})
                        continue
                    requirements = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
                    project_name = ""
                else:
                    continue
                for root_purl in context.root_purls:
                    root_refs = by_purl.get(root_purl, [])
                    if len(root_refs) != 1:
                        continue
                    ref = root_refs[0]
                    item = items[ref]
                    name = canonicalize_name(item.get("name", ""))
                    if project_name and project_name != name:
                        continue
                    metadata.append({"ref": ref, "purl": root_purl, "name": name,
                        "version": item.get("version", item.get("versionInfo")), "requirements": requirements,
                        "evidence_id": r.evidence_id, "authority": "SUPPORTED"})
        # Propagate extras separately by evidence authority. Weak registry/source
        # claims must never activate an extra in a target-verified declaration.
        meta_by_name = {}
        for m in metadata:
            meta_by_name.setdefault(m["name"], {})[m["ref"]] = m
        extras = {m["ref"]: set(context.extras_by_purl.get(m["purl"], [])) if context else set() for m in metadata}
        root = native.data.get("metadata", {}).get("component", {}).get("bom-ref")
        if native.format == "spdx":
            roots = [x.get("relatedSpdxElement") for x in native.data.get("relationships", [])
                     if x.get("relationshipType") == "DESCRIBES"]
        else:
            roots = [root] if root else []
        if context:
            roots += [ref for purl in context.root_purls for ref in by_purl.get(purl, [])]
            roots += [m["ref"] for m in metadata if m["purl"] in context.root_purls and m["authority"] == "VERIFIED_TARGET"]
            for ref in roots:
                extras.setdefault(ref, set()).update(context.active_extras)
        def propagate(rows, state):
            for _ in range(len(metadata) + 1):
                changed = False
                for m in rows:
                    for text in m["requirements"] or []:
                        try:
                            req = Requirement(text)
                        except InvalidRequirement:
                            continue
                        if marker_value(req, context, state[m["ref"]]) is not True:
                            continue
                        for target in rows:
                            if target["name"] != canonicalize_name(req.name):
                                continue
                            try:
                                if req.url or Version(target["version"]) not in req.specifier:
                                    continue
                            except InvalidVersion:
                                continue
                            before = len(state[target["ref"]])
                            state[target["ref"]].update(req.extras)
                            changed |= before != len(state[target["ref"]])
                if not changed:
                    break
            return state
        verified_extras = propagate([m for m in metadata if m["authority"] == "VERIFIED_TARGET"], deepcopy(extras))
        extras = propagate(metadata, extras)
        # Resolve only finite observed/independently extracted target versions. Never choose registry "latest".
        universe = {ref: {"name": canonicalize_name(i.get("name", "")),
                          "version": i.get("version", i.get("versionInfo")), "authority": "SUPPORTED"}
                    for ref, i in items.items()}
        universe.update({m["ref"]: m for m in metadata if m["authority"] == "VERIFIED_TARGET"})
        for m in metadata:
            if m["requirements"] is None:
                self.last_diagnostics.append({"parent": m["ref"], "reason": "EVIDENCE_UNAVAILABLE", "status": "UNKNOWN"})
                continue
            for text in m["requirements"]:
                try:
                    req = Requirement(text)
                    effective_extras = verified_extras[m["ref"]] if m["authority"] == "VERIFIED_TARGET" else extras[m["ref"]]
                    active = marker_value(req, context, effective_extras)
                    if active is None or req.url:
                        self.last_diagnostics.append({"parent": m["ref"], "requirement": text,
                            "reason": "CONTEXT_UNCERTAIN" if active is None else "UNSUPPORTED_DIRECT_URL", "status": "UNKNOWN"})
                        continue
                    if active is not True:
                        continue
                    matches = [(ref, item) for ref, item in universe.items()
                               if item["name"] == canonicalize_name(req.name) and item.get("version")
                               and Version(item["version"]) in req.specifier]
                except (InvalidRequirement, InvalidVersion):
                    self.last_diagnostics.append({"parent": m["ref"], "requirement": text, "reason": "INVALID_REQUIREMENT_OR_VERSION", "status": "UNKNOWN"})
                    continue
                if len(matches) == 1:
                    target, target_item = matches[0]
                    authority = "VERIFIED_TARGET" if context and m["authority"] == target_item["authority"] == "VERIFIED_TARGET" else "SUPPORTED"
                    claims.append({"operation": "add_dependency", "subject": m["ref"], "field": None,
                        "value": target, "evidence_ids": sorted({m["evidence_id"]} |
                            ({target_item["evidence_id"]} if target_item.get("authority") == "VERIFIED_TARGET" else set())), "authority": authority,
                        "context_sha256": sha(context.model_dump()) if context else None,
                        "requirement": text, "extras": sorted(effective_extras), "context_required": True})
                else:
                    self.last_diagnostics.append({"parent": m["ref"], "requirement": text, "status": "UNKNOWN",
                        "reason": "AMBIGUOUS_VERSION_OR_INSTANCE" if matches else "TARGET_NOT_OBSERVED",
                        "candidate_refs": [ref for ref, _ in matches]})
        return claims
