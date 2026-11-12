"""Frozen, allowlisted evidence acquisition for SBOM investigations.

The catalog never executes repository code or performs network requests. Native
tool output needs an explicit collection envelope identifying its target scope.
An envelope is a reproducibility record supplied by the experiment controller,
not a cryptographic build attestation. Its provenance must be audited separately.
Registry metadata supplies upstream candidates, never selected-package truth.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any

from packageurl import PackageURL

from sbom_recovery.reconciliation.merge_contracts_v3 import ReconciliationRequestV3


DENIED_NAMES = {"oracle", "gold", "labels", "annotation", "annotations", "adjudication", "ground_truth"}
RELATIONSHIPS = {"direct_dependency", "contains", "build_input_of"}
TARGET_KINDS = {"manifest", "lockfile", "native_resolution", "build_record", "bundler_metafile"}


def _safe_parts(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or not relative or "\\" in relative or "\x00" in relative or ":" in relative:
        raise ValueError("Unsafe bundle-relative path")
    parts = relative.split("/")
    if PurePosixPath(relative).is_absolute() or any(p in {"", ".", ".."} for p in parts):
        raise ValueError("Unsafe bundle-relative path")
    for part in parts:
        stem = part.casefold().split(".", 1)[0]
        words = set(re.split(r"[-_\s]+", stem))
        if stem in DENIED_NAMES or words.intersection(DENIED_NAMES) or "ground_truth" in stem:
            raise ValueError("Oracle, labels, and adjudication paths are not evidence")
    return tuple(parts)


def read_frozen_blob(base_dir: Path, relative: str, expected_sha256: str, limit: int) -> bytes:
    """Read a regular file through directory descriptors, rejecting every symlink.

    O_NOFOLLOW applies to intermediate directories as well as the final file,
    preventing a path replacement from escaping the allowlisted bundle root.
    The size bound applies before hashing or decoding any content.
    """
    if type(limit) is not int or limit < 0:
        raise ValueError("Invalid byte limit")
    parts = _safe_parts(relative)
    root = Path(base_dir).absolute()
    # Do not silently resolve a symlink supplied as the bundle root.
    if root.is_symlink():
        raise ValueError("Symlink bundle root is not allowed")
    descriptors: list[int] = []
    try:
        current = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(current)
        for part in parts[:-1]:
            current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            descriptors.append(current)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        descriptors.append(fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Evidence must be a regular file")
        if info.st_size > limit:
            raise ValueError("Evidence exceeds source byte limit")
        chunks, count = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            if count > limit:
                raise ValueError("Evidence exceeds source byte limit")
        raw = b"".join(chunks)
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise ValueError("Frozen evidence digest changed")
        return raw
    except OSError as exc:
        raise ValueError("Evidence unavailable or unsafe") from exc
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _empty_facts() -> dict[str, Any]:
    return {"components": [], "edges": [], "coverage": [], "bindings": [], "scope": {}, "roots": [],
            "deferred_components": [], "deferred_edges": []}


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("Expected nonempty " + field)
    return value


def _purl(ecosystem: str, name: str, version: str | None, namespace: str | None = None) -> str:
    if ecosystem == "npm" and name.startswith("@") and "/" in name:
        namespace, name = name.split("/", 1)
    return PackageURL(type=ecosystem, namespace=namespace, name=name, version=version).to_string()


def _validate_components(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise ValueError("components must be an array")
    out, seen = [], set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid component")
        item = {k: deepcopy(row[k]) for k in (
            "occurrence_id", "ecosystem", "name", "version", "purl", "locator", "origin", "digest", "namespace"
        ) if k in row}
        for key in ("occurrence_id", "ecosystem", "name"):
            _text(item.get(key), key)
        if item["occurrence_id"] in seen:
            raise ValueError("Duplicate occurrence ID")
        seen.add(item["occurrence_id"])
        for key in ("version", "purl", "locator", "origin", "digest", "namespace"):
            if key in item and item[key] is not None and not isinstance(item[key], str):
                raise ValueError("Invalid component " + key)
        if item.get("purl"):
            parsed = PackageURL.from_string(item["purl"])
            expected_name = parsed.name
            if parsed.type == "npm" and parsed.namespace:
                expected_name = (parsed.namespace if parsed.namespace.startswith("@") else "@" + parsed.namespace) + "/" + parsed.name
            if parsed.type != item["ecosystem"] or expected_name != item["name"] or parsed.version != item.get("version"):
                # A PURL/name disagreement is evidence conflict, not a value to guess.
                raise ValueError("PURL disagrees with component identity")
            item["purl"] = parsed.to_string()
        elif item.get("version"):
            item["purl"] = _purl(item["ecosystem"], item["name"], item["version"], item.get("namespace"))
        out.append(item)
    return out


def _validate_facts(facts: dict[str, Any]) -> dict[str, Any]:
    facts["components"] = _validate_components(facts["components"])
    known = {r["occurrence_id"] for r in facts["components"]}
    roots = facts.get("roots", [])
    if not isinstance(roots, list) or any(not isinstance(root, str) or root not in known for root in roots):
        raise ValueError("Evidence roots must identify collected occurrences")
    facts["roots"] = sorted(set(roots))
    if not isinstance(facts["edges"], list) or not isinstance(facts["coverage"], list):
        raise ValueError("edges and coverage must be arrays")
    edges = []
    for edge in facts["edges"]:
        if not isinstance(edge, dict) or edge.get("relationship_type") not in RELATIONSHIPS:
            raise ValueError("Unsupported relationship semantics")
        if edge.get("source") not in known or edge.get("target") not in known:
            raise ValueError("Unresolved evidence edge endpoint")
        if "scope" in edge and edge["scope"] is not None and not isinstance(edge["scope"], str):
            raise ValueError("Invalid dependency scope")
        edges.append({k: deepcopy(edge[k]) for k in ("source", "target", "relationship_type", "scope") if k in edge})
    coverage = []
    for row in facts["coverage"]:
        if not isinstance(row, dict) or row.get("domain") not in {"components", "direct_dependency"}:
            raise ValueError("Invalid coverage domain")
        if row.get("subject") != "*" and row.get("subject") not in known:
            raise ValueError("Invalid coverage subject")
        if type(row.get("complete")) is not bool:
            raise ValueError("Coverage complete must be an explicit boolean")
        if "scope" in row and row["scope"] is not None and not isinstance(row["scope"], str):
            raise ValueError("Coverage dependency scope must be a string")
        coverage.append({k: row[k] for k in ("subject", "domain", "complete", "scope") if k in row})
    facts["edges"], facts["coverage"], facts["bindings"] = edges, coverage, []
    return facts


def _npm_name(locator: str) -> str:
    name = locator.rsplit("node_modules/", 1)[-1]
    if not name or name.startswith("/") or "/node_modules/" in name:
        raise ValueError("Cannot infer npm package name")
    return name


def _npm_platform(row: dict[str, Any], context: dict[str, Any]) -> str | None:
    """Return a deferral reason, never infer a host platform or install flag."""
    aliases = {"os": {"windows": "win32", "macos": "darwin", "mac": "darwin"},
               "cpu": {"amd64": "x64", "x86_64": "x64", "aarch64": "arm64",
                       "x86": "ia32", "i386": "ia32", "i686": "ia32", "armv7l": "arm"}}
    dimensions = {"os": context.get("os"), "cpu": context.get("architecture"), "libc": None}
    for field, actual in dimensions.items():
        if field not in row:
            continue
        selectors = row[field]
        if not isinstance(selectors, list) or any(not isinstance(v, str) or not v for v in selectors):
            return "UNKNOWN_PLATFORM_SELECTOR"
        if not selectors:
            continue
        # npm's wildcard is special only as the singleton list ["any"].
        # In a mixed list it is a literal positive selector.
        if selectors == ["any"] and field != "libc":
            continue
        if not isinstance(actual, str) or not actual:
            return "UNKNOWN_PLATFORM_CONTEXT"
        actual = aliases.get(field, {}).get(actual.lower(), actual.lower())
        positive = {v for v in selectors if not v.startswith("!")}
        negative = {v[1:] for v in selectors if v.startswith("!")}
        if positive.intersection(negative):
            return "CONFLICTING_PLATFORM_SELECTOR"
        if actual in negative or (positive and actual not in positive):
            return "INCOMPATIBLE_PLATFORM"
    return None


def _npm_lock(data: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    if data.get("lockfileVersion") not in {2, 3} or not isinstance(data.get("packages"), dict):
        raise ValueError("Only npm lockfile v2/v3 package tables are supported")
    packages = data["packages"]
    if not isinstance(packages.get(""), dict):
        raise ValueError("npm lockfile has no root package record")
    context = context or {}
    facts, candidates, excluded = _empty_facts(), {}, {}
    for locator, row in packages.items():
        if not isinstance(locator, str) or not isinstance(row, dict):
            raise ValueError("Malformed npm package table")
        name = row.get("name") or (data.get("name") if locator == "" else _npm_name(locator))
        version = row.get("version") or (data.get("version") if locator == "" else None)
        if not name or not isinstance(version, str):
            continue
        occurrence = "npm:" + locator
        component = {"occurrence_id": occurrence, "ecosystem": "npm", "name": name,
                     "version": version, "purl": _purl("npm", name, version), "locator": locator}
        if isinstance(row.get("resolved"), str):
            component["origin"] = row["resolved"]
        candidates[locator] = component
        reason = _npm_platform(row, context)
        if row.get("link"):
            reason = "WORKSPACE_LINK_NOT_MATERIALIZED"
        elif row.get("optional") or row.get("devOptional"):
            reason = reason or "OPTIONAL_SELECTION_NOT_ESTABLISHED"
        elif row.get("dev") and context.get("build_profile") not in {"dev", "development", "test", "tests"}:
            reason = reason or "DEVELOPMENT_SELECTION_NOT_ESTABLISHED"
        if reason:
            excluded[locator] = reason
    # Node resolution searches the nearest node_modules directory upwards. An
    # alias declaration resolves by its install name, while identity comes from
    # the installed entry's explicit name/version.
    adjacency: dict[str, list[tuple[str, str]]] = {}
    for locator in packages:
        row = packages[locator]
        optional = row.get("optionalDependencies", {})
        if not isinstance(optional, dict):
            raise ValueError("Invalid npm optional dependency declarations")
        for field, scope in (("dependencies", "runtime"), ("optionalDependencies", "optional"),
                             ("devDependencies", "development")):
            dependencies = row.get(field, {})
            if not isinstance(dependencies, dict):
                raise ValueError("Invalid npm dependency declarations")
            for name in dependencies:
                if not isinstance(name, str) or not name:
                    raise ValueError("Invalid npm dependency name")
                prefixes = [locator]
                cursor = locator
                while cursor:
                    cursor = cursor.rsplit("/node_modules/", 1)[0] if "/node_modules/" in cursor else ""
                    if cursor not in prefixes:
                        prefixes.append(cursor)
                found = next((p + "/node_modules/" + name if p else "node_modules/" + name
                              for p in prefixes if (p + "/node_modules/" + name if p else "node_modules/" + name) in packages), None)
                if found is not None:
                    reason = None
                    if field == "optionalDependencies" or (field == "dependencies" and name in optional):
                        reason = "OPTIONAL_SELECTION_NOT_ESTABLISHED"
                    elif field == "devDependencies" and (locator != "" or context.get("build_profile") not in {"dev", "development", "test", "tests"}):
                        reason = "DEVELOPMENT_SELECTION_NOT_ESTABLISHED"
                    if reason:
                        facts["deferred_edges"].append({"source": "npm:" + locator, "target": "npm:" + found,
                            "relationship_type": "direct_dependency", "scope": scope, "reason": reason})
                    else:
                        adjacency.setdefault(locator, []).append((found, scope))
    # Package tables can retain optional, platform-specific and disconnected
    # entries. Only reachable, eligible resolution records become target facts.
    reached, pending = set(), [""] if "" not in excluded else []
    while pending:
        locator = pending.pop()
        if locator in reached or locator in excluded:
            continue
        if locator != "" and locator not in candidates:
            continue
        reached.add(locator)
        pending.extend(target for target, _ in adjacency.get(locator, []) if target not in reached)
    for locator, component in candidates.items():
        if locator in reached:
            facts["components"].append(component)
        else:
            facts["deferred_components"].append({**component, "reason": excluded.get(locator, "NOT_REACHABLE_FROM_SELECTED_ROOT")})
    for locator in sorted(reached):
        if locator not in candidates:
            continue  # A nameless/versionless root can still bind its resolved dependencies.
        for target, scope in adjacency.get(locator, []):
            if target in reached and target in candidates:
                facts["edges"].append({"source": candidates[locator]["occurrence_id"],
                    "target": candidates[target]["occurrence_id"], "relationship_type": "direct_dependency", "scope": scope})
    # Lockfile declarations may contain peer/optional/platform dependencies;
    # this parser intentionally makes no closed-inventory/outgoing claims.
    facts["roots"] = [candidates[""]["occurrence_id"]] if "" in reached and "" in candidates else []
    return facts


def _npm_ls(data: dict[str, Any]) -> dict[str, Any]:
    facts = _empty_facts()
    if data.get("problems") or data.get("error"):
        raise ValueError("npm ls contains unresolved problems")
    seen: dict[str, str] = {}

    def walk(row: dict[str, Any], locator: str, fallback: str | None = None) -> str | None:
        if not isinstance(row, dict) or row.get("missing") or row.get("invalid") or row.get("problems"):
            return None
        name, version = row.get("name", fallback), row.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            return None
        actual_locator = row.get("path", locator)
        if not isinstance(actual_locator, str):
            raise ValueError("Invalid npm ls path")
        if actual_locator in seen:
            return seen[actual_locator]
        occurrence = "npm:" + actual_locator
        seen[actual_locator] = occurrence
        facts["components"].append({"occurrence_id": occurrence, "ecosystem": "npm", "name": name,
                                    "version": version, "purl": _purl("npm", name, version), "locator": actual_locator})
        dependencies = row.get("dependencies")
        if dependencies is not None and not isinstance(dependencies, dict):
            raise ValueError("Invalid npm ls dependency graph")
        for key, child in (dependencies or {}).items():
            target = walk(child, (locator + "/" if locator else "") + "node_modules/" + key, key)
            if target:
                facts["edges"].append({"source": occurrence, "target": target,
                                       "relationship_type": "direct_dependency", "scope": "unknown"})
        return occurrence

    root = walk(data, "")
    if root is None:
        raise ValueError("npm ls has no identifiable root")
    facts["roots"] = [root]
    # npm ls is a logical graph. Missing dependencies field does not assert []
    # and its successful traversal is not a physical inventory completeness proof.
    return facts


def _cargo_metadata(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data.get("packages"), list) or not isinstance(data.get("resolve"), dict):
        raise ValueError("Cargo metadata requires packages and a resolved graph")
    facts, packages = _empty_facts(), {}
    for row in data["packages"]:
        if not isinstance(row, dict):
            raise ValueError("Invalid Cargo package")
        item = {"occurrence_id": _text(row.get("id"), "Cargo package id"), "ecosystem": "cargo",
                "name": _text(row.get("name"), "Cargo package name"),
                "version": _text(row.get("version"), "Cargo package version")}
        item["purl"] = _purl("cargo", item["name"], item["version"])
        if isinstance(row.get("manifest_path"), str):
            item["locator"] = row["manifest_path"]
        if isinstance(row.get("source"), str):
            item["origin"] = row["source"]
        if item["occurrence_id"] in packages:
            raise ValueError("Duplicate Cargo package ID")
        packages[item["occurrence_id"]] = item
    known = set(packages)
    nodes = data["resolve"].get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("Cargo resolve.nodes missing")
    node_ids = [node.get("id") if isinstance(node, dict) else None for node in nodes]
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("Duplicate Cargo resolve node")
    root = data["resolve"].get("root")
    if root is not None:
        roots = [_text(root, "Cargo root package")]
    elif "workspace_default_members" in data:
        roots = data["workspace_default_members"]
    else:
        roots = data.get("workspace_members")
    if not isinstance(roots, list) or any(not isinstance(v, str) or not v for v in roots):
        raise ValueError("Cargo metadata selected roots are unknown")
    if any(root not in known or root not in node_ids for root in roots):
        raise ValueError("Cargo selected root is absent from package/resolve records")
    possible_edges = []
    for node in nodes:
        source = node.get("id") if isinstance(node, dict) else None
        if source not in known:
            raise ValueError("Unknown Cargo resolve node")
        deps = node.get("deps")
        if deps is None:
            # Older metadata's untyped dependencies can still report unknown
            # scope, but must not be interpreted as runtime-only.
            legacy = node.get("dependencies", [])
            if not isinstance(legacy, list):
                raise ValueError("Invalid legacy Cargo dependencies")
            deps = [{"pkg": d, "dep_kinds": [{"kind": "unknown"}]} for d in legacy]
        if not isinstance(deps, list):
            raise ValueError("Invalid Cargo dependencies")
        for dep in deps:
            target = dep.get("pkg") if isinstance(dep, dict) else None
            if target not in known:
                raise ValueError("Unknown Cargo dependency endpoint")
            kinds = dep.get("dep_kinds")
            if not isinstance(kinds, list) or not kinds:
                kinds = [{"kind": "unknown"}]
            for kind in kinds:
                if not isinstance(kind, dict):
                    raise ValueError("Invalid Cargo dependency kind")
                scope = {None: "runtime", "normal": "runtime", "dev": "development", "build": "build"}.get(kind.get("kind"), "unknown")
                # cargo metadata may contain target-conditional edges for more
                # than one platform. No host default is permitted: defer them.
                edge = {"source": source, "target": target,
                        "relationship_type": "direct_dependency", "scope": scope}
                if kind.get("target") or scope == "unknown" or "kind" not in kind or "target" not in kind:
                    facts["deferred_edges"].append({**edge, "reason": "TARGET_OR_KIND_SELECTION_NOT_ESTABLISHED"})
                    continue
                possible_edges.append(edge)
    adjacency: dict[str, list[str]] = {}
    for edge in possible_edges:
        if edge["target"] not in node_ids:
            facts["deferred_edges"].append({**edge, "reason": "DEPENDENCY_RESOLVE_NODE_MISSING"})
            continue
        adjacency.setdefault(edge["source"], []).append(edge["target"])
    reached, pending = set(), list(roots)
    while pending:
        source = pending.pop()
        if source in reached:
            continue
        reached.add(source)
        pending.extend(target for target in adjacency.get(source, []) if target not in reached)
    for package_id, component in packages.items():
        if package_id in reached:
            facts["components"].append(component)
        else:
            facts["deferred_components"].append({**component, "reason": "NOT_REACHABLE_FROM_UNCONDITIONAL_SELECTED_ROOTS"})
    facts["edges"] = [edge for edge in possible_edges if edge["source"] in reached and edge["target"] in reached]
    facts["roots"] = roots
    return facts


class EvidenceCatalog:
    """A frozen catalog of source IDs; callers cannot supply filesystem paths."""

    def __init__(self, request: ReconciliationRequestV3, base_dir: Path, max_source_bytes: int = 1048576):
        if type(max_source_bytes) is not int or max_source_bytes < 0:
            raise ValueError("Invalid source byte limit")
        self.request = request
        self.base_dir = Path(base_dir).absolute()
        self.max_source_bytes = max_source_bytes
        self.sources = {source.source_id: source for source in request.evidence}

    def descriptors(self) -> list[dict[str, Any]]:
        return [{"source_id": row.source_id, "kind": row.kind, "sha256": row.blob.sha256,
                 "description": "Frozen " + row.kind + " evidence (untrusted data)"}
                for row in self.sources.values()]

    def _scope(self, payload: dict[str, Any]) -> dict[str, str]:
        supplied = payload.get("target")
        target = self.request.target
        expected = {"target_id": target.target_id, "revision_ref": target.revision_ref,
                    "context_id": target.context.context_id, "view": target.view}
        if expected["revision_ref"] is None:
            raise ValueError("Unknown target revision cannot bind target evidence")
        if not isinstance(supplied, dict) or any(supplied.get(k) != v or supplied.get(k) is None for k, v in expected.items()):
            raise ValueError("Evidence scope is missing or differs from requested target/revision/context/view")
        return expected

    def _parse(self, payload: Any, kind: str) -> tuple[dict[str, Any], list[str], bool]:
        if not isinstance(payload, dict):
            raise ValueError("Evidence JSON must be an object")
        warnings: list[str] = []
        if kind == "registry_metadata":
            if payload.get("schema_version") == "reconciliation-evidence-v1":
                rows = payload.get("components", [])
            else:
                row = payload.get("info", payload)
                ecosystem = payload.get("ecosystem", "pypi" if "info" in payload else "npm")
                rows = [{"occurrence_id": "upstream:" + str(row.get("name", "unknown")),
                         "ecosystem": ecosystem, "name": row.get("name"), "version": row.get("version")}]
            facts = _empty_facts()
            facts["components"] = _validate_components(rows)
            return facts, ["Registry metadata does not prove selected or installed presence"], True
        if kind not in TARGET_KINDS:
            raise ValueError("Source kind has no target-fact collector")
        scope = self._scope(payload)
        if kind in {"lockfile", "native_resolution"} and scope["view"] != "RESOLVED":
            raise ValueError("Lockfile/native resolution facts require the RESOLVED view")
        if kind == "manifest" and scope["view"] != "DECLARED":
            raise ValueError("Manifest declarations do not establish resolved or artifact presence")
        schema = payload.get("schema_version")
        if schema == "reconciliation-evidence-v1":
            facts = {"components": payload.get("components", []), "edges": payload.get("edges", []), "roots": payload.get("roots", []),
                     "coverage": payload.get("coverage", []), "bindings": [], "scope": scope}
            if payload.get("bindings"):
                warnings.append("Snapshot-supplied observation bindings ignored; bind independently using locators")
            if kind in {"manifest", "lockfile"} and scope["view"] == "ARTIFACT":
                raise ValueError("Manifest/lockfile does not establish artifact contents")
            for edge in facts["edges"]:
                if not isinstance(edge, dict):
                    raise ValueError("Invalid relationship")
                relationship = edge.get("relationship_type")
                if relationship == "direct_dependency" and scope["view"] == "ARTIFACT":
                    raise ValueError("Artifact containment is not a direct-dependency graph")
                if relationship == "contains" and scope["view"] != "ARTIFACT":
                    raise ValueError("Containment requires the ARTIFACT view")
                if relationship == "build_input_of" and scope["view"] != "RESOLVED":
                    raise ValueError("Build inputs require the RESOLVED view")
            return _validate_facts(facts), warnings, False
        if schema != "native-evidence-v1" or not isinstance(payload.get("data"), dict):
            raise ValueError("Native evidence requires a scoped collection envelope")
        if scope["view"] != "RESOLVED":
            raise ValueError("Package-manager resolution is only evidence for the RESOLVED view")
        parsers = {"npm-lock": _npm_lock, "npm-ls": _npm_ls, "cargo-metadata": _cargo_metadata}
        fmt = payload.get("format")
        if fmt not in parsers:
            raise ValueError("Unsupported native evidence format")
        facts = parsers[fmt](payload["data"], self.request.target.context.model_dump()) if fmt == "npm-lock" else parsers[fmt](payload["data"])
        facts["scope"] = scope
        warnings.append("Native graph is scoped collection evidence; physical/shipped inventory completeness is not asserted")
        if facts["deferred_components"] or facts["deferred_edges"]:
            warnings.append("Deferred conditional, optional or unselected records remain candidates; no target presence or closure inferred")
        return _validate_facts(facts), warnings, False

    def acquire(self, source_id: str, remaining_bytes: int | None = None) -> dict[str, Any]:
        result = {"source_id": source_id, "kind": None, "sha256": None, "bytes_returned": 0,
                  "status": "ERROR", "facts": _empty_facts(), "content_role": "UNTRUSTED_DATA"}
        if not isinstance(source_id, str) or source_id not in self.sources:
            result["error"] = "Evidence source ID is not allowlisted"
            return result
        source = self.sources[source_id]
        result.update(kind=source.kind, sha256=source.blob.sha256)
        if remaining_bytes is not None and (type(remaining_bytes) is not int or remaining_bytes < 0):
            result["error"] = "Invalid remaining byte budget"
            return result
        try:
            raw = read_frozen_blob(self.base_dir, source.blob.path, source.blob.sha256, self.max_source_bytes)
            consumed = min(len(raw), remaining_bytes) if remaining_bytes is not None else len(raw)
            result["bytes_returned"] = consumed
            if consumed < len(raw):
                raise ValueError("Evidence exceeds remaining byte budget; no partial facts admitted")
            if source.kind == "artifact_bytes":
                artifact = self.request.target.artifact
                actual = hashlib.sha256(raw).hexdigest()
                matches = artifact is not None and actual == artifact.artifact.sha256
                result.update(status="OK", artifact_digest={"algorithm": "SHA-256", "value": actual,
                    "object": "COMPLETE_SUPPLIED_SOURCE_BYTES", "binding": "DIRECT_ARTIFACT" if matches else "UNBOUND"},
                    limitations=["Artifact hash alone does not establish a component identity or dependency edge"],
                    candidate_only=True)
                return result
            payload = json.loads(raw)
            facts, limitations, candidate_only = self._parse(payload, source.kind)
            result.update(status="OK", facts=facts, limitations=limitations, candidate_only=candidate_only)
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
            # No provider response bodies, raw paths or file contents in errors.
            result["error"] = str(exc)[:300] or "Invalid evidence"
        return result
