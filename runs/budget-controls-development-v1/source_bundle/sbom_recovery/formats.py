"""Lossless native documents; graph views never collapse occurrences by PURL."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from packageurl import PackageURL
from packaging.utils import canonicalize_name


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def canonical_purl(value):
    p = PackageURL.from_string(value)
    if p.type == "pypi":
        p = p._replace(name=canonicalize_name(p.name))
    return p.to_string()  # Keep qualifiers and subpath: they may identify another build.


def package_purl(item, fmt):
    raw = item.get("purl") if fmt == "cyclonedx" else next(
        (r.get("referenceLocator") for r in item.get("externalRefs", [])
         if r.get("referenceType") == "purl"), None)
    try:
        return canonical_purl(raw) if raw else None
    except (ValueError, TypeError):
        return None


class NativeDocument:
    def __init__(self, document):
        self.data = deepcopy(document)
        if document.get("bomFormat") == "CycloneDX":
            self.format, self.id_field = "cyclonedx", "bom-ref"
        elif str(document.get("spdxVersion", "")).startswith("SPDX-2."):
            self.format, self.id_field = "spdx", "SPDXID"
        else:
            raise ValueError("Expected native CycloneDX JSON or SPDX 2.x JSON")

    def entities(self):
        if self.format == "spdx":
            return self.data.get("packages", []) + self.data.get("files", [])

        def walk(items):
            for item in items:
                yield item
                yield from walk(item.get("components", []))
        root = self.data.get("metadata", {}).get("component")
        return list(walk(([root] if root else []) + self.data.get("components", [])))

    def index(self):
        items = self.entities()
        counts = Counter(i.get(self.id_field) for i in items if i.get(self.id_field))
        return {i[self.id_field]: i for i in items if counts.get(i.get(self.id_field)) == 1}

    def packages(self):
        return {ref: item for ref, item in self.index().items()
                if (self.format == "spdx" and "fileName" not in item)
                or (self.format == "cyclonedx" and item.get("type") != "file")}

    def edges(self):
        if self.format == "cyclonedx":
            return {(d["ref"], t) for d in self.data.get("dependencies", []) for t in d.get("dependsOn", [])}
        out = set()
        for r in self.data.get("relationships", []):
            if r.get("relationshipType") == "DEPENDS_ON":
                out.add((r["spdxElementId"], r["relatedSpdxElement"]))
            elif r.get("relationshipType") == "DEPENDENCY_OF":
                out.add((r["relatedSpdxElement"], r["spdxElementId"]))
        return out

    def declaration(self, ref):
        if self.format == "cyclonedx":
            rows = [d for d in self.data.get("dependencies", []) if d.get("ref") == ref]
            if rows:
                return set(t for d in rows for t in d.get("dependsOn", []))
        return None

    def issues(self):
        items, idx = self.entities(), self.index()
        counts = Counter(i.get(self.id_field) for i in items)
        errors = [{"code": "DUPLICATE_REF", "ref": r} for r, n in counts.items() if r and n > 1]
        if counts.get(None):
            errors.append({"code": "MISSING_REF", "count": counts[None]})
        errors.extend({"code": "DANGLING_DEPENDENCY", "edge": list(e)} for e in sorted(self.edges())
                      if any(n not in idx for n in e))
        if self.format == "spdx":
            known = set(idx) | {self.data.get("SPDXID", "SPDXRef-DOCUMENT"), "NONE", "NOASSERTION"}
            for r in self.data.get("relationships", []):
                for k in ("spdxElementId", "relatedSpdxElement"):
                    ref = r.get(k)
                    if ref not in known and not (isinstance(ref, str) and ref.startswith("DocumentRef-")):
                        errors.append({"code": "DANGLING_REFERENCE", "ref": ref})
        return errors

    def apply(self, proposal):
        p = proposal.model_dump() if hasattr(proposal, "model_dump") else proposal
        if p["operation"] == "set_field":
            entity = self.index()[p["subject"]]
            if entity.get(p["field"]) != p.get("before"):
                raise ValueError("STALE_PRECONDITION")
            entity[p["field"]] = deepcopy(p["value"])
        elif p["operation"] == "add_component":
            if p["subject"] in self.index():
                raise ValueError("EXISTING_REF")
            key = "components" if self.format == "cyclonedx" else "packages"
            self.data.setdefault(key, []).append(deepcopy(p["value"]))
        else:
            source, target = p["subject"], p["value"]
            if source not in self.index() or target not in self.index():
                raise ValueError("UNRESOLVED_ENDPOINT")
            if self.format == "spdx":
                row = {"spdxElementId": source, "relatedSpdxElement": target, "relationshipType": "DEPENDS_ON"}
                if (source, target) not in self.edges():
                    self.data.setdefault("relationships", []).append(row)
            else:
                rows = self.data.setdefault("dependencies", [])
                row = next((r for r in rows if r.get("ref") == source), None)
                if row is None:
                    row = {"ref": source, "dependsOn": []}
                    rows.append(row)
                if target not in row.setdefault("dependsOn", []):
                    row["dependsOn"].append(target)

    def summary(self):
        return {"format": self.format, "input_sha256": sha(self.data), "issues": self.issues(),
                "components": [{"ref": r, "purl": package_purl(i, self.format),
                                "name": i.get("name"), "version": i.get("version", i.get("versionInfo"))}
                               for r, i in self.packages().items()],
                "edges": sorted(map(list, self.edges())), "path_absence_status": "UNKNOWN"}


def validate_native(document):
    native = NativeDocument(document)
    errors = native.issues()
    if native.format == "cyclonedx":
        from research_core import validate_cdx
        result = validate_cdx(document)
        errors += result["errors"]
    else:
        # Use the independent SPDX parser + semantic validator; do not merely stamp a version.
        from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
        from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
        try:
            parsed = JsonLikeDictParser().parse(document)
            errors += [{"code": "SPDX_SEMANTIC", "message": str(e)} for e in validate_full_spdx_document(parsed)]
        except Exception as exc:
            errors.append({"code": "SPDX_PARSE", "message": str(exc)})
    return {"valid": not errors, "format": native.format, "errors": errors}


def cyclonedx_projection(document, root_purls=()):
    """Explicit export only; upstream completeness is always scored on native SPDX."""
    native = NativeDocument(document)
    if native.format == "cyclonedx":
        return deepcopy(document), {"conversion": "NONE", "lossless": True}
    result = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": [],
              "metadata": {"properties": [{"name": "sbom-recovery:interpretation", "value": "Candidate SBOM; no exploitability assertion"}]}}
    mappings = []
    for ref, item in native.index().items():
        kind = "file" if "fileName" in item else "library"
        converted = {"type": kind, "bom-ref": ref, "name": item.get("name", item.get("fileName", ref)),
                     "properties": [{"name": "sbom-recovery:native-record", "value": encoded(item).decode()}]}
        if item.get("versionInfo"):
            converted["version"] = item["versionInfo"]
        purl = package_purl(item, "spdx")
        if purl:
            converted["purl"] = purl
        if item.get("licenseDeclared") not in (None, "NOASSERTION", "NONE", ""):
            converted["licenses"] = [{"expression": item["licenseDeclared"]}]
        if purl in root_purls:
            converted["type"] = "application"
            if "component" not in result["metadata"]:
                result["metadata"]["component"] = converted
            else:
                result["components"].append(converted)
        else:
            result["components"].append(converted)
        mappings.append({"spdx_ref": ref, "bom_ref": ref, "native_fields_preserved_in_property": sorted(item)})
    edges = {}
    for source, target in sorted(native.edges()):
        edges.setdefault(source, []).append(target)
    if edges:
        result["dependencies"] = [{"ref": ref, "dependsOn": targets} for ref, targets in edges.items()]
    result["metadata"]["properties"].append({"name": "sbom-recovery:native-document", "value": encoded(document).decode()})
    return result, {"conversion": "SPDX_TO_CYCLONEDX_PROJECTION", "lossless_native_sidecar": True,
                    "semantic_mapping_complete": False, "mappings": mappings,
                    "completeness_evaluation": "DO_NOT_USE_PROJECTION_FOR_UPSTREAM_FIELD_COMPARISON"}
