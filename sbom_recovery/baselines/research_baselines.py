"""B4: hypothetical package-manager resolution, with an explicit information budget."""
from collections import defaultdict, deque

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.specifiers import SpecifierSet


def b4_from_report(report, root_requirements):
    """Build B4 predictions from resolver output, never from installed metadata labels."""
    index = {canonicalize_name(r["metadata"]["name"]): r["metadata"] for r in report["install"]}
    environment = report["environment"]
    extras = defaultdict(set)
    roots = []
    for raw in root_requirements:
        req = Requirement(raw)
        name = canonicalize_name(req.name)
        roots.append(name)
        extras[name].update(canonicalize_name(x) for x in req.extras)
    queue, seen, edges, unresolved = deque(roots), {}, set(), []
    while queue:
        name = queue.popleft()
        state = frozenset(extras[name])
        if seen.get(name) == state:
            continue
        seen[name] = state
        metadata = index.get(name)
        if metadata is None:
            unresolved.append({"parent": name, "reason": "RESOLUTION_RECORD_MISSING"})
            continue
        for raw in metadata.get("requires_dist", []) or []:
            try:
                req = Requirement(raw)
                active = not req.marker or any(req.marker.evaluate({**environment, "extra": extra}) for extra in [""] + sorted(state))
                if not active:
                    continue
                child = canonicalize_name(req.name)
                if child not in index or (req.specifier and index[child]["version"] not in SpecifierSet(str(req.specifier))):
                    unresolved.append({"parent": name, "requirement": raw, "reason": "UNRESOLVED_OR_INCOMPATIBLE"})
                    continue
                edges.add((f"pkg:pypi/{name}@{metadata['version']}", f"pkg:pypi/{child}@{index[child]['version']}"))
                before = set(extras[child])
                extras[child].update(canonicalize_name(x) for x in req.extras)
                if child not in seen or before != extras[child]:
                    queue.append(child)
            except Exception as exc:
                unresolved.append({"parent": name, "requirement": raw, "reason": str(exc)})
    return {"baseline_id": "B4", "baseline_name": "Package-manager resolution reference",
            "information_budget": "PRIVILEGED_MANIFEST_ENVIRONMENT_AND_FROZEN_PUBLIC_ARTIFACT_SET",
            "interpretation": "Hypothetical resolved graph; target installation needs independent verification",
            "predicted_edges": sorted(edges), "predicted_nodes": sorted(f"pkg:pypi/{name}@{index[name]['version']}" for name in seen if name in index),
            "unresolved": unresolved, "root_requirements": root_requirements}
