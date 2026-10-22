#!/usr/bin/env python3
"""SBOM graph completion + security impact PoC (stdlib only).

Fixture: fictional packages and fictional advisory; no real CVE claim.
Live: best-effort deps.dev generic resolution and OSV query; NOT a build ground truth.

This is a deterministic evidence-based BASELINE, not a trained AI model.
"""
import argparse
import ast
from collections import deque
from copy import deepcopy
import json
from pathlib import Path
import sys
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

HERE = Path(__file__).resolve().parent


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def purl_parts(purl):
    # Only PyPI package-URLs in this small PoC. Do not parse general purls this way.
    prefix = "pkg:pypi/"
    if not isinstance(purl, str) or not purl.startswith(prefix) or "@" not in purl:
        return None
    name, version = purl[len(prefix):].rsplit("@", 1)
    if not name or not version or "/" in name or "?" in version or "#" in version:
        return None
    return name.lower().replace("_", "-").replace(".", "-"), version


def normalized_purl(purl):
    details = purl_parts(purl)
    return "pkg:pypi/%s@%s" % details if details else purl


def get_json(url, timeout=12):
    request = Request(url, headers={"User-Agent": "sbom-security-poc/0.1"})
    with urlopen(request, timeout=timeout) as response:
        return json.load(response)


def post_json(url, body, timeout=12):
    request = Request(url, data=json.dumps(body).encode(),
                      headers={"User-Agent": "sbom-security-poc/0.1", "Content-Type": "application/json"},
                      method="POST")
    with urlopen(request, timeout=timeout) as response:
        return json.load(response)


class EvidenceProvider:
    def __init__(self, fixture=None):
        self.fixture = read_json(fixture) if fixture else None
        self.graph_cache = {}
        self.warnings = []

    def dependencies(self, purl):
        purl = normalized_purl(purl)
        if purl in self.graph_cache:
            return self.graph_cache[purl]
        if self.fixture is not None:
            # None means unknown; [] means known empty (the distinction matters).
            result = self.fixture.get("dependencies", {}).get(purl)
        else:
            parts = purl_parts(purl)
            if not parts:
                result = None
            else:
                name, version = parts
                url = ("https://api.deps.dev/v3/systems/pypi/packages/" +
                       quote(name, safe="") + "/versions/" +
                       quote(version, safe="") + ":dependencies")
                try:
                    data = get_json(url)
                    if data.get("error") or any(n.get("errors") for n in data.get("nodes", [])):
                        self.warnings.append("Unresolved dependency data for " + purl)
                        result = None
                    else:
                        nodes = data.get("nodes", [])
                        # Direct outgoing edges of root only. Each node is queried
                        # individually to avoid accidentally conflating contexts.
                        result = []
                        for e in data.get("edges", []):
                            if e["fromNode"] == 0:
                                v = nodes[e["toNode"]]["versionKey"]
                                if v.get("system", "").upper() == "PYPI":
                                    result.append("pkg:pypi/%s@%s" % (v["name"], v["version"]))
                except (HTTPError, URLError, TimeoutError, ValueError, KeyError, IndexError) as exc:
                    self.warnings.append("No metadata for %s: %s" % (purl, str(exc)))
                    result = None
        if result is not None:
            result = list(dict.fromkeys(normalized_purl(p) for p in result))
        self.graph_cache[purl] = result
        return result


class AdvisoryProvider:
    def __init__(self, fixture=None):
        self.fixture = read_json(fixture) if fixture else None
        self.warnings = []

    def query(self, purl):
        if self.fixture is not None:
            return self.fixture.get("advisories", {}).get(purl, [])
        parts = purl_parts(purl)
        if not parts:
            return []
        try:
            name, version = parts
            data = post_json("https://api.osv.dev/v1/query", {
                "version": version, "package": {"name": name, "ecosystem": "PyPI"}
            })
            # Fail closed to 'unknown', not 'safe', on pagination/API errors.
            vulns = data.get("vulns", [])
            if data.get("next_page_token"):
                self.warnings.append("OSV response paginated for " + purl + "; results incomplete")
            return [{"id": v["id"], "title": v.get("summary", ""), "kind": "real_advisory"}
                    for v in vulns if "id" in v]
        except (HTTPError, URLError, TimeoutError, ValueError, KeyError) as exc:
            self.warnings.append("OSV query unavailable for %s: %s" % (purl, str(exc)))
            return None


def shortest_path(graph, start, end):
    todo = deque([(start, [start])])
    visited = {start}
    while todo:
        node, path = todo.popleft()
        if node == end:
            return path
        for nxt in sorted(graph.get(node, [])):
            if nxt not in visited:
                visited.add(nxt)
                todo.append((nxt, path + [nxt]))
    return None


def flatten_attribute(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def simple_static_callgraph(source):
    """Very limited static Python calls: from-import and direct function calls.
    Does not soundly handle dispatch, methods, decorators, aliases, reflection,
    dynamic imports, conditional execution, or packages missing from source.
    """
    source = Path(source)
    module_info = {}
    for path in source.rglob("*.py"):
        rel = path.relative_to(source).with_suffix("")
        parts = list(rel.parts)
        if parts[-1] == "__init__":
            parts.pop()
        module = ".".join(parts)
        if not module:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        import_map = {}
        functions = {}
        for stmt in tree.body:
            if isinstance(stmt, ast.ImportFrom) and stmt.module and stmt.level == 0:
                for item in stmt.names:
                    if item.name != "*":
                        import_map[item.asname or item.name] = stmt.module + "." + item.name
            elif isinstance(stmt, ast.Import):
                for item in stmt.names:
                    import_map[item.asname or item.name.split(".")[0]] = item.name
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[stmt.name] = stmt
        module_info[module] = (import_map, functions)
    graph = {}
    all_functions = {module + "." + fname for module, (_, functions) in module_info.items()
                     for fname in functions}
    for module, (import_map, functions) in module_info.items():
        for fname, func in functions.items():
            caller = module + "." + fname
            callees = set()
            for n in ast.walk(func):
                if not isinstance(n, ast.Call):
                    continue
                called = flatten_attribute(n.func)
                if not called:
                    continue
                first, *rest = called.split(".")
                if first in import_map:
                    target = ".".join([import_map[first]] + rest)
                elif "." not in called:
                    target = module + "." + called
                else:
                    target = called
                if target in all_functions:
                    callees.add(target)
            graph[caller] = callees
    return graph


def reconstruct(sbom, evidence, max_components=60):
    new_sbom = deepcopy(sbom)
    roots = [new_sbom.get("metadata", {}).get("component", {})]
    existing_components = roots + new_sbom.get("components", [])
    purl_to_ref = {}
    ref_to_purl = {}
    for c in existing_components:
        ref, purl = c.get("bom-ref"), c.get("purl")
        if ref and purl and purl_parts(purl):
            key = normalized_purl(purl)
            # Ambiguous purl should not be silently collapsed.
            if key in purl_to_ref and purl_to_ref[key] != ref:
                raise ValueError("Same PURL occurs under multiple bom-refs: " + key)
            purl_to_ref[key] = ref
            ref_to_purl[ref] = key

    known = set(purl_to_ref)
    deps = {e["ref"]: set(e.get("dependsOn", [])) for e in new_sbom.get("dependencies", [])}
    # Explicit entries are treated as complete for their direct dependents.
    # This PoC never overrides an explicit declaration.
    explicit = set(deps)
    inferred_nodes = []
    inferred_edges = []
    queue = deque((p, 0) for p in sorted(known))
    visited = set()
    blocked = []
    while queue:
        parent, depth = queue.popleft()
        if parent in visited:
            continue
        visited.add(parent)
        if depth > 4:
            blocked.append("Depth limit reached for " + parent)
            continue
        # Still queue declared packages to infer their own outgoing edges.
        if ref_to_purl and parent not in purl_to_ref:
            continue
        if purl_to_ref[parent] in explicit:
            continue
        children = evidence.dependencies(parent)
        if children is None:
            continue
        source_ref = purl_to_ref[parent]
        deps.setdefault(source_ref, set())
        for child in children:
            if not purl_parts(child):
                blocked.append("Invalid/unhandled package: " + child)
                continue
            if child not in purl_to_ref:
                if len(purl_to_ref) >= max_components:
                    blocked.append("Component limit reached, skipped " + child)
                    continue
                name, version = purl_parts(child)
                ref = child
                new_sbom.setdefault("components", []).append({
                    "type": "library", "bom-ref": ref,
                    "purl": child, "name": name, "version": version
                })
                purl_to_ref[child] = ref
                ref_to_purl[ref] = child
                inferred_nodes.append(child)
            target_ref = purl_to_ref[child]
            if target_ref not in deps[source_ref]:
                deps[source_ref].add(target_ref)
                inferred_edges.append({
                    "from": parent, "to": child,
                    "source": "fixture_metadata" if evidence.fixture else "deps.dev_reference_resolution",
                    "claim": "candidate_not_verified_in_target_build"
                })
            if child not in visited:
                queue.append((child, depth + 1))

    # BFS over newly discovered refs may have skipped a pre-existing component whose
    # dependency list was explicitly supplied; preserve those edges.
    new_sbom["dependencies"] = [
        {"ref": ref, "dependsOn": sorted(children)}
        for ref, children in sorted(deps.items())
    ]
    graph = {ref: set(children) for ref, children in deps.items()}
    for ref in ref_to_purl:
        graph.setdefault(ref, set())
    return new_sbom, purl_to_ref, graph, inferred_nodes, inferred_edges, blocked


def main():
    parser = argparse.ArgumentParser(description="SBOM completion & reachability PoC")
    parser.add_argument("--live", action="store_true", help="Use deps.dev & OSV external APIs, instead of fictional fixture")
    parser.add_argument("--input", type=Path, help="CycloneDX JSON SBOM")
    parser.add_argument("--source", type=Path, help="Optional source tree for LIMITED Python static call analysis")
    parser.add_argument("--entry", default="app.main", help="Static analysis entry function")
    parser.add_argument("--out", type=Path, default=HERE / "results" / "demo")
    parser.add_argument("--max-components", type=int, default=60)
    args = parser.parse_args()

    sbom_file = args.input or (HERE / "fixtures" / ("sbom_live_requests.json" if args.live else "sbom_incomplete.json"))
    sbom = read_json(sbom_file)
    fixture = None if args.live else HERE / "fixtures" / "registry.json"
    fixture_advisories = None if args.live else HERE / "fixtures" / "advisories.json"
    evidence = EvidenceProvider(fixture)
    advisories = AdvisoryProvider(fixture_advisories)
    root = sbom.get("metadata", {}).get("component", {})
    root_ref = root.get("bom-ref")
    if not root_ref:
        raise ValueError("SBOM must declare metadata.component.bom-ref")

    old_comps = len(sbom.get("components", [])) + 1
    old_edges = sum(len(item.get("dependsOn", [])) for item in sbom.get("dependencies", []))
    final_sbom, purl_refs, graph, inferred_nodes, inferred_edges, blocked = reconstruct(
        sbom, evidence, args.max_components)

    callgraph = simple_static_callgraph(args.source) if args.source else None
    findings = []
    for purl, ref in sorted(purl_refs.items()):
        reports = advisories.query(purl)
        if reports is None:  # cannot query != no known vulnerabilities
            findings.append({"component": purl, "status": "advisory_lookup_unknown"})
            continue
        for advisory in reports:
            dep_path_refs = shortest_path(graph, root_ref, ref)
            dep_path = [final_sbom.get("metadata", {}).get("component", {}).get("purl", root_ref)]
            dep_path = [next((p for p, r in purl_refs.items() if r == x), x)
                        for x in dep_path_refs] if dep_path_refs else None
            target = advisory.get("function")
            code_path = shortest_path(callgraph, args.entry, target) if callgraph and target else None
            if not dep_path:
                fn_status = "unknown"
            elif code_path:
                fn_status = "static_call_path_found_demo_only"
            else:
                fn_status = "unknown_not_proven_unreachable"
            findings.append({
                "advisory": advisory["id"], "title": advisory.get("title", ""),
                "advisory_kind": advisory.get("kind", "unknown"),
                "component": purl,
                "dependency_path": dep_path,
                "dependency_path_status": "candidate_path" if dep_path else "not_observed",
                "vulnerable_function": target,
                "function_reachability": fn_status,
                "static_call_path": code_path
            })

    report = {
        "run_mode": "live_best_effort" if args.live else "fully_synthetic_offline_fixture",
        "not_an_ai_model": True,
        "scope": "Python/PyPI; candidate dependency edges, not validated against installed artifacts",
        "before": {"components": old_comps, "edges": old_edges},
        "after": {"components": len(purl_refs), "edges": sum(len(x) for x in graph.values())},
        "recovered_components": inferred_nodes,
        "candidate_edges": inferred_edges,
        "security_findings": findings,
        "blocked": blocked,
        "warnings": evidence.warnings + advisories.warnings,
        "limitations": [
            "Fixture packages and fixture advisory are entirely invented (not real vulnerabilities).",
            "Live deps.dev resolution is for a generic environment; not evidence of actual installation.",
            "OSV package/version match does not establish vulnerable-code execution.",
            "Limited Python static call graph supports a small subset of call patterns.",
            "A missing call path means UNKNOWN, never PROVEN_UNREACHABLE.",
            "Explicit dependency declarations are preserved and not contradicted."
        ]
    }
    args.out.mkdir(parents=True, exist_ok=True)
    save_json(args.out / "reconstructed.cdx.json", final_sbom)
    save_json(args.out / "report.json", report)
    from dashboard import write_dashboard
    write_dashboard(args.out / "dashboard.html", sbom, final_sbom, report)
    print("MODE:", report["run_mode"])
    print("SBOM: %d components / %d edges  ->  %d components / %d edges" % (
        old_comps, old_edges, report["after"]["components"], report["after"]["edges"]))
    print("New components:", inferred_nodes)
    print("Candidate edges:", [(e["from"], e["to"]) for e in inferred_edges])
    for finding in findings:
        if finding.get("advisory"):
            print("ADVISORY:", finding["advisory"], "on", finding["component"])
            print("  dependency path:", " -> ".join(finding["dependency_path"] or []) or "none observed")
            print("  function:", finding["function_reachability"])
            if finding.get("static_call_path"):
                print("  static call path:", " -> ".join(finding["static_call_path"]))
    if report["warnings"]:
        print("WARNINGS:", len(report["warnings"]), "(see report.json)")
    print("Output:", args.out.resolve())
    # Simple fixture-only test vs known ground truth. Not an empirical result.
    if not args.live and sbom_file.resolve() == (HERE / "fixtures" / "sbom_incomplete.json").resolve():
        truth = read_json(HERE / "fixtures" / "ground_truth.json")
        got = {(e["from"], e["to"]) for e in inferred_edges}
        expected = {tuple(pair) for pair in truth["missing_edges"]}
        tp = len(got & expected)
        precision = tp / len(got) if got else 0
        recall = tp / len(expected) if expected else 0
        print("FIXTURE CHECK: recovered %d/%d omitted edges, precision=%.2f, recall=%.2f" %
              (tp, len(expected), precision, recall))


if __name__ == "__main__":
    main()
