"""B5: declared CycloneDX topology and conservative Level 1 path evidence.

Taxonomy adapted from Zieba-Kozarzewski (2026), arXiv:2607.22140v1,
Section III, equations (1)-(2). That source is a preprint, not a verified
peer-reviewed publication. Normative absence semantics: CycloneDX 1.5,
dependencies/compositions. No completeness claim is inferred from topology.
"""
from collections import Counter, defaultdict, deque


def _entities(document):
    def walk(items, child_key):
        for item in items:
            yield item
            yield from walk(item.get(child_key, []), child_key)

    root = document.get("metadata", {}).get("component")
    yield from walk(([root] if root else []) + document.get("components", []), "components")
    yield from walk(document.get("services", []), "services")


def declared_graph(document):
    """Use bom-ref, retaining files/services and refusing ambiguous identifiers."""
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("B5 currently supports CycloneDX JSON only")
    entities = list(_entities(document))
    counts = Counter(item.get("bom-ref") for item in entities if item.get("bom-ref"))
    duplicates = sorted(ref for ref, count in counts.items() if count > 1)
    missing = sum(not item.get("bom-ref") for item in entities)
    nodes = {item["bom-ref"]: item for item in entities
             if item.get("bom-ref") and counts[item["bom-ref"]] == 1}
    dependencies = document.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError("dependencies must be an array when present")
    edges, unresolved, declarations, empty = set(), [], set(), set()
    for index, item in enumerate(dependencies):
        source = item.get("ref")
        targets = item.get("dependsOn", [])
        if not isinstance(targets, list):
            raise ValueError("dependsOn must be an array")
        if source in nodes:
            declarations.add(source)
            if not targets:
                empty.add(source)
        else:
            unresolved.append({"record": index, "source": source, "reason": "UNKNOWN_OR_AMBIGUOUS_SOURCE"})
        for target in targets:
            if source in nodes and target in nodes:
                edges.add((source, target))
            else:
                unresolved.append({"record": index, "source": source, "target": target,
                                   "reason": "UNKNOWN_OR_AMBIGUOUS_ENDPOINT"})
    return nodes, edges, {"duplicate_refs": duplicates, "unaddressable_entities": missing,
                          "unresolved_relationships": unresolved,
                          "declared_sources": sorted(declarations), "explicit_empty_sources": sorted(empty)}


def topology(document):
    nodes, edges, audit = declared_graph(document)
    adjacent = defaultdict(set)
    for source, target in edges:
        adjacent[source].add(target)
        adjacent[target].add(source)
    orphans = sorted(ref for ref in nodes if not adjacent[ref])
    rho = len(orphans) / len(nodes) if nodes else None
    remaining, groups = set(nodes), 0
    while remaining:
        queue = [remaining.pop()]
        groups += 1
        while queue:
            for child in adjacent[queue.pop()]:
                if child in remaining:
                    remaining.remove(child)
                    queue.append(child)
    block = "dependencies" in document
    regime = ("EMPTY_GRAPH" if not nodes else "no_edges" if not block else
              "degenerate-with-edges" if rho > 0.5 else "connected")
    compositions = [{"aggregate": item.get("aggregate", "not_specified"),
                     "dependencies": item.get("dependencies", []),
                     "assemblies": item.get("assemblies", [])}
                    for item in document.get("compositions", [])]
    return {"regime": regime, "dependency_block_present": block, "nodes": len(nodes), "edges": len(edges),
            "orphan_count": len(orphans), "orphan_ratio": rho, "orphan_refs": orphans,
            "edges_per_node": len(edges) / len(nodes) if nodes else None,
            "weak_components": groups, "orphan_threshold": 0.5,
            "identity_scope": "All uniquely referenced components (including metadata root/nested components) and services",
            "graph_index_status": "PARTIAL" if any(audit[k] for k in
                ("duplicate_refs", "unaddressable_entities", "unresolved_relationships")) else "RESOLVED_DECLARED_REFERENCES",
            "declared_source_count": len(audit["declared_sources"]),
            "explicit_empty_source_count": len(audit["explicit_empty_sources"]),
            "composition_claims": compositions, "completeness": "UNVERIFIED_PRODUCER_CLAIMS" if compositions else "UNKNOWN",
            "audit": audit,
            "interpretation": "connected is a topology class; it does not certify graph completeness or runtime reachability"}


def b5_assess(document, roots=None, targets=None):
    """Explicit roots only; absence ALWAYS abstains, including connected graphs.

    Paths establish only a declared dependency path. A producer's complete
    composition is preserved with its exact scope, never trusted as installation
    proof or expanded to transitive descendants.
    """
    nodes, edges, _ = declared_graph(document)
    if roots is None:
        ref = document.get("metadata", {}).get("component", {}).get("bom-ref")
        roots = [ref] if ref else []
    roots = sorted(set(roots))
    targets = sorted(set(nodes if targets is None else targets))
    adjacent = defaultdict(list)
    for source, target in sorted(edges):
        adjacent[source].append(target)
    predecessors = {ref: None for ref in roots if ref in nodes}
    queue = deque(predecessors)
    while queue:
        source = queue.popleft()
        for target in adjacent[source]:
            if target not in predecessors:
                predecessors[target] = source
                queue.append(target)
    assessments = []
    for target in targets:
        path, status, level = [], "UNKNOWN", None
        reason = "NO_DECLARED_DEPENDENCY_PATH"
        if target not in nodes:
            reason = "TARGET_NOT_OBSERVED_OR_AMBIGUOUS"
        elif target in predecessors:
            cursor = target
            while cursor is not None:
                path.append(cursor)
                cursor = predecessors[cursor]
            path.reverse()
            status, level, reason = (("ROOT_COMPONENT", 0, "DECLARED_ROOT") if len(path) == 1 else
                                     ("DEPENDENCY_PATH_OBSERVED", 1, "DECLARED_DIRECT_EDGES"))
        elif not predecessors:
            reason = "ROOT_NOT_DECLARED_OR_NOT_OBSERVED"
        assessments.append({"target_ref": target, "target_purl": nodes.get(target, {}).get("purl"),
                            "status": status, "evidence_level": level, "path_refs": path, "reason": reason,
                            "openvex_status": "under_investigation"})
    return {"baseline_id": "B5", "information_budget": "DECLARED_SBOM_AND_EXPLICIT_ROOTS_ONLY",
            "topology": topology(document), "root_refs": roots,
            "unresolved_root_refs": [ref for ref in roots if ref not in nodes], "assessments": assessments,
            "counts": dict(Counter(row["status"] for row in assessments)),
            "security_metrics": {"vrr": None, "openvex_triage_delta": None, "false_assurance_reduction": None,
                                 "status": "UNMEASURED_NO_INDEPENDENT_ADVISORY_OR_PRODUCT_LABELS"},
            "interpretation": "Path evidence is Level 1 only. Every absent path remains UNKNOWN; no VEX impact assertion is emitted."}
