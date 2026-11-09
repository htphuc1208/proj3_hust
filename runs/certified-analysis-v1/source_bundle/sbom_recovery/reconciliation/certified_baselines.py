"""Strong semantic control without certificates; never a deliberately weak foil.

The control shares the declared semantic trusted base with V2. Equality is an
important possible outcome: certificates do not create new input information.
"""
from copy import deepcopy

from packaging.utils import canonicalize_name

from sbom_recovery.core.formats import NativeDocument
from .certified_evidence import EvidenceView
from .certified_semantics import activation_bounds, marker_bounds


def metadata_control(document, context, manifest, acquired, *, additive_only=False, assessments=False):
    view = EvidenceView(document, context, manifest, acquired)
    lower, upper, _ = activation_bounds(view, context)
    original = NativeDocument(document)
    result = NativeDocument(document)
    removals, supported = set(), set()
    # Direct interpretation of acquired declarations, no proposal generator,
    # certificates, checker, node addition or identity rewriting.
    for ref, key in sorted(view.bound.items()):
        parent = view.distributions[key]
        for _, _, req in parent.requirements:
            child = view.unique_child(req)
            if (child in view.reverse and marker_bounds(req, context, lower[key]) is True):
                result.apply({"operation": "add_dependency", "subject": ref, "value": view.reverse[child]})
                supported.add((ref, view.reverse[child]))
        if additive_only or not parent.complete:
            continue
        for source, target in original.edges():
            if source != ref or target not in view.bound:
                continue
            child = view.distributions[view.bound[target]]
            matches = [r for r in parent.requirements if canonicalize_name(r[2].name) == child.name]
            if not matches or all(marker_bounds(req, context, lower[key], upper[key] if upper is not None else None) is False
                                  for _, _, req in matches):
                removals.add((source, target))
    if result.format == "cyclonedx":
        for row in result.data.get("dependencies", []):
            row["dependsOn"] = [t for t in row.get("dependsOn", []) if (row["ref"], t) not in removals]
    else:
        def retain(row):
            kind = row.get("relationshipType")
            edge = row.get("spdxElementId"), row.get("relatedSpdxElement")
            if kind == "DEPENDENCY_OF":
                edge = edge[::-1]
            return kind not in {"DEPENDS_ON", "DEPENDENCY_OF"} or edge not in removals
        result.data["relationships"] = [r for r in result.data.get("relationships", []) if retain(r)]
    if assessments:
        decisions = [{"source_ref": s, "target_ref": t,
            "status": "SUPPORTED" if (s, t) in supported else "REFUTED" if (s, t) in removals else "UNKNOWN"}
            for s, t in sorted(original.edges() | supported)]
        return deepcopy(result.data), decisions
    return deepcopy(result.data)
