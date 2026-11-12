"""Frozen OSV matching and dependency exposure; no exploitability conclusions.

The range algorithm follows https://ossf.github.io/osv-schema/#evaluation .
Unsupported version schemes and malformed records return UNKNOWN. This module
does not access registries, execute code, or consult evaluation labels.
"""
from __future__ import annotations

from collections import Counter, deque
import hashlib
import json
import re

from packageurl import PackageURL


ENGINE = {"name": "eager-osv-offline", "version": "1", "scope": "package-version"}
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def _version(value):
    """SemVer precedence, ignoring build metadata; reject noncanonical versions."""
    match = _SEMVER.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("Unsupported semantic version")
    major, minor, patch, pre, _ = match.groups()
    parts = []
    for part in pre.split(".") if pre else []:
        if part.isdigit():
            if len(part) > 1 and part.startswith("0"):
                raise ValueError("Numeric prerelease identifier has a leading zero")
            parts.append((0, int(part)))
        else:
            parts.append((1, part))
    return int(major), int(minor), int(patch), 0 if pre else 1, tuple(parts)


def _ecosystem(value):
    return {"crates.io": "cargo", "rust": "cargo", "pypi": "pypi"}.get(str(value).lower(), str(value).lower())


def _name(value, ecosystem):
    name = str(value)
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def identity(component):
    """Return ecosystem/name/version, rejecting contradictory PURL coordinates."""
    eco = _ecosystem(component.get("ecosystem", ""))
    name, version = component.get("name"), component.get("version")
    if component.get("purl"):
        try:
            p = PackageURL.from_string(component["purl"])
        except (ValueError, TypeError):
            return None
        p_name = (p.namespace + "/" if p.namespace else "") + p.name
        p_eco = _ecosystem(p.type)
        # Some component representations keep namespace separately.
        full_name = str(name or "")
        namespace = component.get("namespace")
        if namespace and not full_name.startswith(namespace + "/"):
            full_name = namespace + "/" + full_name
        if eco and eco != p_eco:
            return None
        if name and _name(full_name, p_eco) != _name(p_name, p_eco):
            return None
        if version and p.version and version != p.version:
            return None
        eco, name, version = p_eco, p_name, version or p.version
    elif component.get("namespace"):
        namespace = component["namespace"]
        if not str(name or "").startswith(namespace + "/"):
            name = namespace + "/" + str(name or "")
    if not eco or not name:
        return None
    return eco, _name(name, eco), version


def _package_matches(component_identity, package):
    if component_identity is None or not isinstance(package, dict):
        return False
    eco, name, _ = component_identity
    if package.get("purl"):
        candidate = identity({"purl": package["purl"]})
        if candidate is None or candidate[:2] != (eco, name):
            return False
        # Reject internal package-name/PURL disagreement.
        if package.get("name") and _name(package["name"], eco) != name:
            return False
        return not package.get("ecosystem") or _ecosystem(package["ecosystem"]) == eco
    return _ecosystem(package.get("ecosystem", "")) == eco and _name(package.get("name", ""), eco) == name


def _range_matches(version, item, ecosystem):
    if not isinstance(item, dict):
        return None
    if item.get("type") != "SEMVER" and not (
        item.get("type") == "ECOSYSTEM" and ecosystem in {"npm", "cargo"}
    ):
        return None
    events = item.get("events")
    if not isinstance(events, list) or not events:
        return None
    try:
        value = _version(version)
        parsed, limits, keys = [], [], set()
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                return None
            key, text = next(iter(event.items()))
            if key not in {"introduced", "fixed", "last_affected", "limit"}:
                return None
            keys.add(key)
            if key == "limit":
                limits.append(None if text == "*" else _version(text))
            else:
                parsed.append(((-1,) if key == "introduced" and text == "0" else _version(text), key))
        if "introduced" not in keys or {"fixed", "last_affected"} <= keys:
            return None
        if limits and not any(limit is None or value < limit for limit in limits):
            return False
        # Equal-version contradictory events have unspecified meaning: abstain.
        if len({v for v, _ in parsed}) != len(parsed):
            return None
        affected = False
        for event_version, key in sorted(parsed):
            if key == "introduced" and value >= event_version:
                affected = True
            elif key == "fixed" and value >= event_version:
                affected = False
            elif key == "last_affected" and value > event_version:
                affected = False
        return affected
    except (ValueError, TypeError):
        return None


def affected_version(version, entry, ecosystem):
    """True/False/None for a matching OSV affected entry, never a safety label."""
    if not isinstance(version, str) or not version:
        return None
    versions, ranges = entry.get("versions", []), entry.get("ranges", [])
    if not isinstance(versions, list) or any(not isinstance(v, str) for v in versions):
        return None
    if not isinstance(ranges, list):
        return None
    if version in versions:
        return True
    outcomes = [_range_matches(version, r, ecosystem) for r in ranges]
    if True in outcomes:
        return True
    if None in outcomes:
        return None
    if ranges or versions:
        return False
    return None


def _advisory_groups(advisories):
    """Connected alias groups; `related` identifiers do not imply equivalence."""
    records, groups = [], []
    for row in advisories:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise ValueError("Each advisory needs an ID")
        if row.get("withdrawn"):
            continue
        aliases = row.get("aliases", [])
        if not isinstance(aliases, list) or any(not isinstance(v, str) for v in aliases):
            raise ValueError("Invalid advisory aliases")
        ids = {row["id"], *aliases}
        matches = [i for i, group in enumerate(groups) if group & ids]
        for i in reversed(matches):
            ids |= groups.pop(i)
        groups.append(ids)
        records.append(row)
    for ids in sorted(groups, key=lambda g: sorted(g)):
        yield sorted(ids), [row for row in records if row["id"] in ids]


def observed_paths(result):
    """Only supported direct dependencies between supported occurrences count."""
    verified = {c["id"] for c in result.get("components", []) if c.get("status") == "SUPPORTED"}
    adjacency = {}
    for edge in result.get("edges", []):
        if (edge.get("status") == "SUPPORTED" and edge.get("relationship_type") == "direct_dependency"
                and edge.get("source") in verified and edge.get("target") in verified):
            adjacency.setdefault(edge["source"], set()).add(edge["target"])
    paths, pending = {}, deque()
    for root in result.get("roots", []):
        if root in verified:
            paths[root] = [root]
            pending.append(root)
    while pending:
        source = pending.popleft()
        for target in sorted(adjacency.get(source, set())):
            if target not in paths:
                paths[target] = paths[source] + [target]
                pending.append(target)
    return paths


def assess(result, snapshot):
    """Match all retained component claims against one immutable OSV snapshot."""
    if snapshot.get("schema_version") != "osv-snapshot-v1" or not isinstance(snapshot.get("advisories"), list):
        raise ValueError("Expected osv-snapshot-v1 with advisories")
    findings, unknowns, paths = [], [], observed_paths(result)
    groups = list(_advisory_groups(snapshot["advisories"]))
    for component in result.get("components", []):
        if component.get("status") == "REFUTED":
            continue
        ident = identity(component)
        if ident is None:
            unknowns.append({"component_id": component["id"], "reason": "UNRESOLVED_PACKAGE_IDENTITY"})
            continue
        matched = False
        for aliases, records in groups:
            entries = [entry for row in records for entry in row.get("affected", [])
                       if isinstance(entry, dict) and _package_matches(ident, entry.get("package"))]
            if not entries:
                continue
            matched = True
            outcomes = [affected_version(ident[2], entry, ident[0]) for entry in entries]
            affected = True if True in outcomes else None if None in outcomes else False
            supported = component.get("status") == "SUPPORTED"
            status = ("CONFIRMED_AFFECTED" if supported else "POTENTIALLY_AFFECTED") if affected is True else (
                "NOT_IN_AFFECTED_RANGE" if affected is False and supported else "UNKNOWN")
            path = paths.get(component["id"])
            findings.append({"component_id": component["id"], "advisory_id": aliases[0], "aliases": aliases,
                             "record_ids": sorted(row["id"] for row in records), "status": status,
                             "affected_version": affected, "component_status": component.get("status", "UNKNOWN"),
                             "dependency_exposure": "OBSERVED_PATH" if path else "UNKNOWN", "path": path,
                             "exploitability": "NOT_ASSESSED", "evidence_ids": component.get("evidence_ids", [])})
        if not matched:
            unknowns.append({"component_id": component["id"], "reason": "NO_MATCH_IN_SNAPSHOT",
                             "interpretation": "Database non-match does not establish safety"})
    return {"schema_version": "reconciliation-security-v1", "snapshot_sha256": digest(snapshot),
            "matching_engine": ENGINE, "consumer": snapshot.get("consumer"), "findings": findings,
            "unknowns": unknowns, "summary": dict(Counter(f["status"] for f in findings)),
            "path_absence_status": "UNKNOWN", "exploitability": "NOT_ASSESSED"}
