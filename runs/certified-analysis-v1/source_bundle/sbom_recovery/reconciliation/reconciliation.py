"""Development baseline v1: assess existing PyPI edges using bound target bytes.

Only demonstrably inactive declarations can be retracted from a separate view.
No oracle, registry, inferred installation, or host marker defaults are used.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import re

from packageurl import PackageURL
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from sbom_recovery.core.contracts import TargetContext
from sbom_recovery.core.formats import NativeDocument, canonical_purl, sha, validate_native
from sbom_recovery.evidence.storage import save
from sbom_recovery.campaign.targets import metadata_inventory

POLICY = "inactive-declaration-reconciliation-v1"
MARKER_FIELDS = ("os_name", "sys_platform", "platform_machine", "python_version",
                 "python_full_version", "platform_system")
UNKNOWN_MARKERS = ("platform_release", "platform_version", "implementation_version",
                   "platform_python_implementation", "implementation_name", "extras", "dependency_groups")


def marker(requirement, context, extras):
    if requirement.marker is None:
        return True
    if context is None or any(re.search(r"\b" + key + r"\b", str(requirement.marker))
                              for key in UNKNOWN_MARKERS):
        return None
    environment = {key: getattr(context, key) for key in MARKER_FIELDS}
    return any(requirement.marker.evaluate({**environment, "extra": extra})
               for extra in set(extras) | {""})


def bare_purl(value):
    """Qualified builds cannot be bound from Name/Version alone."""
    parsed = PackageURL.from_string(value)
    if parsed.type != "pypi" or not parsed.version or parsed.qualifiers or parsed.subpath or parsed.namespace:
        raise ValueError("Unbound package identity")
    return canonical_purl(value)


def load_snapshot(target, context, available_at):
    # available_at must come from trusted capture provenance, not a model's claim.
    horizon = datetime.fromisoformat(context.evidence_cutoff.replace("Z", "+00:00"))
    acquired = datetime.fromisoformat(available_at.replace("Z", "+00:00"))
    if acquired.tzinfo is None or acquired > horizon:
        raise ValueError("Target metadata is after cutoff or has unknown availability")
    root = Path(target).resolve(strict=True)
    paths, binding = metadata_inventory(root)
    if context.target_id != binding:
        raise ValueError("Target metadata inventory digest does not match context")
    items, diagnostics = {}, []
    sources = []
    for path in paths:
        if path.parent.parent.name not in {"site-packages", "dist-packages"}:
            continue
        raw = path.read_bytes()
        relative = str(path.relative_to(root))
        source = {"path": relative, "sha256": hashlib.sha256(raw).hexdigest()}
        sources.append(source)
        message = BytesParser().parsebytes(raw)
        if message.defects or len(message.get_all("Name", [])) != 1 or len(message.get_all("Version", [])) != 1:
            diagnostics.append({**source, "reason": "INVALID_METADATA_IDENTITY"})
            continue
        name, version = canonicalize_name(message["Name"]), message["Version"]
        try:
            if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
                raise ValueError("Invalid distribution name")
            Version(version)
            purl = bare_purl(f"pkg:pypi/{name}@{version}")
        except (ValueError, InvalidVersion):
            diagnostics.append({**source, "reason": "INVALID_METADATA_IDENTITY"})
            continue
        requirements = []
        if any("requires-dist" in value.lower() for value in message.get_all("Dynamic", [])):
            diagnostics.append({**source, "reason": "DYNAMIC_REQUIREMENTS"})
        for text in message.get_all("Requires-Dist", []):
            try:
                requirements.append((text, Requirement(text)))
            except InvalidRequirement:
                diagnostics.append({**source, "reason": "INVALID_REQUIREMENT"})
        if purl in items:
            diagnostics.append({**source, "reason": "DUPLICATE_METADATA_IDENTITY"})
        items[purl] = {**source, "purl": purl, "name": name, "version": version,
                       "requirements": requirements}
    # Detect a target changed while the snapshot was being parsed as well.
    if metadata_inventory(root)[1] != binding:
        raise ValueError("Target metadata changed during capture")
    return {"target_id": binding, "available_at": available_at, "items": items,
            "sources": sources, "diagnostics": diagnostics}


def activate_extras(snapshot, context):
    items = deepcopy(snapshot["items"])
    diagnostics = list(snapshot["diagnostics"])
    by_name = defaultdict(list)
    for purl, item in items.items():
        by_name[item["name"]].append(item)
        item["known"] = {canonicalize_name(x) for x in context.extras_by_purl.get(purl, [])}
        if purl in context.root_purls:
            item["known"].update(canonicalize_name(x) for x in context.active_extras)
        item["possible"] = set(item["known"])
    if not context.root_purls or any(p not in items for p in context.root_purls):
        diagnostics.append({"reason": "ROOT_CONTEXT_INCOMPLETE"})
    if any(p not in items for p in context.extras_by_purl):
        diagnostics.append({"reason": "EXTRAS_CONTEXT_UNBOUND"})
    if any(len(rows) > 1 for rows in by_name.values()):
        diagnostics.append({"reason": "MULTIPLE_METADATA_VERSIONS"})
    for state in ("known", "possible"):
        changed = True
        while changed:
            changed = False
            for item in items.values():
                for _, req in item["requirements"]:
                    active = marker(req, context, item[state])
                    if active is False or (state == "known" and (active is not True or req.url)):
                        continue
                    matches = [candidate for candidate in by_name[canonicalize_name(req.name)]
                               if req.url or req.specifier.contains(candidate["version"], prereleases=True)]
                    if state == "known" and len(matches) != 1:
                        continue
                    if not matches and req.extras:
                        diagnostics.append({"reason": "EXTRA_TARGET_UNAVAILABLE", "source": item["path"]})
                    for match in matches:
                        before = set(match[state])
                        match[state].update(canonicalize_name(x) for x in req.extras)
                        changed |= before != match[state]
    return items, diagnostics


def identities(document):
    native = NativeDocument(document)
    result, counts = {}, Counter()
    for ref, package in native.packages().items():
        raw = ([package.get("purl")] if native.format == "cyclonedx" else
               [r.get("referenceLocator") for r in package.get("externalRefs", []) if r.get("referenceType") == "purl"])
        try:
            if len(set(raw)) != 1 or not raw[0]:
                continue
            result[ref] = bare_purl(raw[0])
            counts[result[ref]] += 1
        except (TypeError, ValueError):
            continue
    return {ref: purl for ref, purl in result.items() if counts[purl] == 1}


def reconcile(document, context, snapshot):
    """Return assessments and a derived view; never mutate observation bytes."""
    native = NativeDocument(document)
    before = sha(document)
    if context.target_id != snapshot["target_id"]:
        raise ValueError("Evidence belongs to another target")
    if datetime.fromisoformat(snapshot["available_at"].replace("Z", "+00:00")) > datetime.fromisoformat(
            context.evidence_cutoff.replace("Z", "+00:00")):
        raise ValueError("Evidence is after context cutoff")
    items, diagnostics = activate_extras(snapshot, context)
    bound = identities(document)
    assessments, retracted = [], set()
    for source, target in sorted(native.edges()):
        parent, child = items.get(bound.get(source)), items.get(bound.get(target))
        row = {"source_ref": source, "target_ref": target, "status": "UNKNOWN",
               "reason": "UNBOUND_OR_AMBIGUOUS_INSTANCE", "declarations": [], "evidence": []}
        if parent is not None and child is not None:
            row["evidence"] = [{k: item[k] for k in ("path", "sha256")} for item in (parent, child)]
            row["known_extras"] = sorted(parent["known"])
            row["possible_extras"] = sorted(parent["possible"])
            matches = [(text, req) for text, req in parent["requirements"]
                       if canonicalize_name(req.name) == child["name"]]
            for text, req in matches:
                row["declarations"].append({"text": text, "active": marker(req, context, parent["known"]),
                    "possibly_active": marker(req, context, parent["possible"]),
                    "version_matches": None if req.url else req.specifier.contains(child["version"], prereleases=True)})
            declarations = row["declarations"]
            if diagnostics:
                row["reason"] = "INCOMPLETE_METADATA_OR_CONTEXT"
            elif declarations and all(d["possibly_active"] is False for d in declarations):
                row.update(status="CONTRADICTED", reason="ALL_MATCHING_DECLARATIONS_INACTIVE")
                retracted.add((source, target))
            elif any(d["active"] is True and d["version_matches"] is True for d in declarations):
                row.update(status="SUPPORTED", reason="ACTIVE_VERSION_COMPATIBLE_DECLARATION")
            else:
                row["reason"] = "NO_CONCLUSIVE_DECLARATION"
        assessments.append(row)
    derived = deepcopy(document)
    if native.format == "cyclonedx":
        for row in derived.get("dependencies", []):
            row["dependsOn"] = [t for t in row.get("dependsOn", []) if (row["ref"], t) not in retracted]
        if retracted:
            derived["version"] = derived.get("version", 1) + 1
    else:
        def keep(row):
            kind = row.get("relationshipType")
            edge = (row.get("spdxElementId"), row.get("relatedSpdxElement"))
            if kind == "DEPENDENCY_OF":
                edge = edge[::-1]
            return kind not in {"DEPENDS_ON", "DEPENDENCY_OF"} or edge not in retracted
        derived["relationships"] = [r for r in derived.get("relationships", []) if keep(r)]
    assert sha(document) == before
    return {"policy": POLICY, "input_sha256": before, "output_sha256": sha(derived),
            "context_sha256": sha(context.model_dump()), "target_id": context.target_id,
            "evidence_available_at": snapshot["available_at"], "evidence_sources": snapshot["sources"],
            "assessments": assessments, "counts": dict(Counter(r["status"] for r in assessments)),
            "retracted_edges": sorted(map(list, retracted)), "diagnostics": diagnostics,
            "document": derived, "path_absence_status": "UNKNOWN", "confidence": None,
            "scope": "Target metadata declarations; runtime use and exploitability unmeasured"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("input", "context", "target", "available-at", "out"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    out = Path(args.out)
    if out.exists():
        raise FileExistsError(out)
    document = json.loads(Path(args.input).read_text())
    context = TargetContext.model_validate_json(Path(args.context).read_text())
    snapshot = load_snapshot(args.target, context, args.available_at)
    result = reconcile(document, context, snapshot)
    validation = validate_native(result["document"])
    result["validation"] = validation
    # Invalid exports never become usable repaired SBOMs.
    derived = result.pop("document")
    out.mkdir(parents=True)
    save(out / "observation.json", document)
    save(out / ("reconciled.json" if validation["valid"] else "candidate-invalid.json"), derived)
    save(out / "assessment.json", result)
    save(out / "seal.json", {"policy": POLICY, "input_sha256": result["input_sha256"],
         "prediction_sha256": sha(derived), "assessment_sha256": sha(result),
         "context_sha256": result["context_sha256"], "target_id": context.target_id,
         "reference_labels_read": False, "llm_api_calls": 0})
    print(json.dumps({"policy": POLICY, "counts": result["counts"], "valid": validation["valid"]}))


if __name__ == "__main__":
    main()
