"""B6: interpret a frozen deps.dev v3 graph as remote candidate evidence.

API semantics: https://docs.deps.dev/api/v3/#getdependencies . The remote
generic Linux resolution is never target ground truth or a historical replay.
"""
from packaging.utils import canonicalize_name

from sbom_recovery.core.resolver import normalize_purl


def dependencies_url(root_purl):
    from urllib.parse import quote
    root = normalize_purl(root_purl)
    if not root.startswith("pkg:pypi/") or "@" not in root:
        raise ValueError("B6 requires an observed exact PyPI identity")
    name, version = root[len("pkg:pypi/"):].rsplit("@", 1)
    if not name or not version:
        raise ValueError("Empty package name or version")
    return ("https://api.deps.dev/v3/systems/PYPI/packages/" + quote(name, safe="") +
            "/versions/" + quote(version, safe="") + ":dependencies")


def b6_from_response(response, root_purl, provenance, target_context=None):
    """Decode direct edges; never replace remote versions with oracle versions."""
    root = normalize_purl(root_purl)
    nodes, issues = [], []
    for index, node in enumerate(response.get("nodes", [])):
        key = node.get("versionKey", {})
        if key.get("system") != "PYPI" or not key.get("name") or not key.get("version"):
            nodes.append(None)
            issues.append({"node": index, "reason": "UNSUPPORTED_OR_INCOMPLETE_IDENTITY"})
        else:
            nodes.append(f"pkg:pypi/{canonicalize_name(key['name'])}@{key['version']}")
        if node.get("errors"):
            issues.append({"node": index, "reason": "REMOTE_NODE_ERRORS", "errors": node["errors"]})
    if response.get("error"):
        issues.append({"reason": "REMOTE_GRAPH_ERROR", "error": response["error"]})
    root_matches = bool(nodes) and nodes[0] == root
    if not root_matches:
        issues.append({"reason": "REMOTE_ROOT_MISMATCH", "requested": root, "returned": nodes[0] if nodes else None})
    edges, evidence = set(), []
    for index, edge in enumerate(response.get("edges", [])):
        source, target = edge.get("fromNode"), edge.get("toNode")
        if any(type(i) is not int or i < 0 or i >= len(nodes) for i in (source, target)):
            issues.append({"edge": index, "reason": "INVALID_NODE_INDEX"})
            continue
        if nodes[source] is None or nodes[target] is None:
            issues.append({"edge": index, "reason": "UNRESOLVED_ENDPOINT"})
            continue
        if root_matches:
            pair = (nodes[source], nodes[target])
            edges.add(pair)
            evidence.append({"source_purl": pair[0], "target_purl": pair[1], "remote_edge_index": index,
                             "requirement": edge.get("requirement"), "status": "REMOTE_RESOLUTION_CANDIDATE",
                             "context": "Context-Uncertain", "provenance": provenance})
    return {"baseline_id": "B6", "root_purl": root,
            "status": "ABSTAIN" if not root_matches else "PARTIAL" if issues else "REMOTE_GRAPH_AVAILABLE",
            "information_budget": "OBSERVED_EXACT_ROOT_AND_EXTERNAL_DEPS_DEV_GRAPH",
            "predicted_nodes": sorted({node for node in nodes if node}) if root_matches else [],
            "predicted_edges": sorted(edges), "edge_evidence": evidence, "unresolved": issues,
            "provenance": provenance, "target_context": target_context,
            "environment_alignment": {"status": "Context-Uncertain", "remote_os": "generic 64-bit Linux",
                                      "python_version": "UNKNOWN", "active_extras": "NOT_TARGET_SPECIFIED",
                                      "target_installation_verified": False},
            "temporal_alignment": "RETROSPECTIVE_REMOTE_SNAPSHOT; historical resolution and release cutoff unverified",
            "admissible_as_target_installation_truth": False,
            "interpretation": "Remote hypothetical resolution only; preserve exact remote versions and all errors. No runtime or VEX impact assertion."}
