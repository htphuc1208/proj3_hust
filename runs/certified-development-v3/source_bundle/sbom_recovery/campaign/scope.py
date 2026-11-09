"""Declared installed-distribution view, independent of oracle membership.

Raw native records are always preserved. Source inventory and vendored metadata
are separate scopes, not false packages or proven absent dependencies.
"""
from copy import deepcopy
from collections import defaultdict
import re
from sbom_recovery.core.formats import NativeDocument, package_purl, sha


def installed_candidates(document):
    native = NativeDocument(document)
    candidates, audit = {}, []
    locations = defaultdict(list)
    if native.format == "spdx":
        files = {f.get("SPDXID"): f.get("fileName", "") for f in document.get("files", [])}
        for relationship in document.get("relationships", []):
            if relationship.get("relationshipType") == "CONTAINS" and relationship.get("relatedSpdxElement") in files:
                locations[relationship.get("spdxElementId")].append(files[relationship["relatedSpdxElement"]].replace("\\", "/"))
    for ref, item in native.packages().items():
        purl = package_purl(item, native.format)
        origin = item.get("sourceInfo", "")
        properties = " ".join(str(p.get("value", "")) for p in item.get("properties", []) if "location" in p.get("name", ""))
        paths = locations[ref]
        evidence = (origin + " " + properties + " " + " ".join(paths)).replace("\\", "/")
        metadata_paths = [p for p in paths if p.endswith(".dist-info/METADATA")]
        top_level = any(re.search(r"(?:^|/)(?:site|dist)-packages/[^/]+\.dist-info/METADATA$", p) for p in metadata_paths)
        role = "DISTRIBUTION_CANDIDATE"
        if not purl or not purl.startswith("pkg:pypi/"):
            role = "NON_PYPI_INVENTORY"
        elif not top_level and ("/_vendor/" in evidence or "/vendored/" in evidence):
            role = "VENDORED_INVENTORY"
        elif not top_level and ("/tests/data/" in evidence or "/test/data/" in evidence):
            role = "TEST_METADATA_FIXTURE"
        elif metadata_paths and not top_level:
            role = "NESTED_DISTRIBUTION_METADATA"
        if role == "DISTRIBUTION_CANDIDATE":
            candidates[ref] = item
        audit.append({"ref": ref, "purl": purl, "role": role, "origin_evidence": evidence,
                      "excluded_from_installed_distribution_view": role != "DISTRIBUTION_CANDIDATE"})
    return candidates, audit


def installed_view(document, root_purls=()):
    """Explicit benchmark profile, not a lossy format adapter. Preserve the raw artifact separately.

    File/source inventory is evaluated in the source track. Carrying every binary
    and source-file record into each package-graph mask would change the population
    being masked and make the 39-field source comparison inapplicable.
    """
    native = NativeDocument(document)
    eligible, audit = installed_candidates(document)
    result = deepcopy(document)
    kept = set(eligible)
    if native.format == "spdx":
        result["packages"] = [deepcopy(item) for item in document.get("packages", []) if item.get("SPDXID") in kept]
        result.pop("files", None)
        doc_ref = result.get("SPDXID", "SPDXRef-DOCUMENT")
        result["relationships"] = [deepcopy(r) for r in document.get("relationships", [])
            if r.get("spdxElementId") in kept | {doc_ref} and r.get("relatedSpdxElement") in kept]
        for ref, item in eligible.items():
            if package_purl(item, "spdx") in root_purls:
                row = {"spdxElementId": doc_ref, "relatedSpdxElement": ref, "relationshipType": "DESCRIBES"}
                if row not in result["relationships"]:
                    result["relationships"].append(row)
        if result.get("annotations"):
            result["annotations"] = [a for a in result["annotations"] if a.get("spdxElementId", doc_ref) in kept | {doc_ref}]
    else:
        root = result.get("metadata", {}).get("component", {})
        if root.get("bom-ref") not in kept:
            result.get("metadata", {}).pop("component", None)
        result["components"] = [deepcopy(item) for ref, item in eligible.items() if ref != root.get("bom-ref")]
        if "dependencies" in document:
            result["dependencies"] = [{**r, "dependsOn": [t for t in r.get("dependsOn", []) if t in kept]}
                                      for r in document["dependencies"] if r.get("ref") in kept]
    return result, {"profile": "INSTALLED_PYPI_DISTRIBUTION_VIEW", "raw_sha256": sha(document),
                    "view_sha256": sha(result), "records": audit, "raw_file_count": len(document.get("files", [])),
                    "raw_preservation": "Original native SBOM remains immutable in capture artifacts",
                    "field_coverage_scope": "Source 39-field comparison uses the original source SBOMs, not this profile"}
