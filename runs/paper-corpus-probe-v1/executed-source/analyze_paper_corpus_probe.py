"""Describe paper-corpus differences; never treat source/installed scopes as identical."""
from collections import Counter
import json
from pathlib import Path
import sys
import tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name as canon


def load(path):
    return json.loads(Path(path).read_text())


def save(path, obj):
    Path(path).write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def direct_url_matches(requirement, distribution, git_bindings=None):
    claim = distribution.get("direct_url") or {}
    url = requirement.url
    if not url:
        return True
    if url.startswith("git+"):
        repository, _, revision = url[4:].rpartition("@")
        vcs = claim.get("vcs_info", {})
        bound_commit = (git_bindings or {}).get(repository + "@" + revision)
        return repository.rstrip("/") == claim.get("url", "").rstrip("/") and (
            revision in {vcs.get("requested_revision"), vcs.get("commit_id")}
            or bound_commit is not None and bound_commit == vcs.get("commit_id"))
    return url.split("#")[0] == claim.get("url", "").split("#")[0]


def declaration_graph(inventory, seeds=None, git_bindings=None):
    items = {canon(d["name"]): d for d in inventory["distributions"]}
    if len(items) != len(inventory["distributions"]):
        raise ValueError("Ambiguous installed distribution names")
    requirements = {n: [Requirement(r) for r in d["requirements"]] for n, d in items.items()}
    extras = {n: {canon(e) for e in (seeds or {}).get(n, [])} for n in items}

    def active(parent, req):
        return req.marker is None or any(req.marker.evaluate(environment={**inventory["environment"], "extra": e})
                                         for e in {"", *extras[parent]})

    def endpoint(req):
        name = canon(req.name)
        if name not in items:
            return None
        if not req.specifier.contains(items[name]["version"], prereleases=True):
            return None
        if req.url and not direct_url_matches(req, items[name], git_bindings):
            return None
        return name

    changed = True
    while changed:
        changed = False
        for parent, reqs in requirements.items():
            for req in reqs:
                child = endpoint(req)
                if child and active(parent, req):
                    additions = {canon(e) for e in req.extras} - extras[child]
                    extras[child].update(additions)
                    changed |= bool(additions)
    edges, unresolved, citations = set(), [], {}
    for parent, reqs in requirements.items():
        for req in reqs:
            if active(parent, req):
                child = endpoint(req)
                if child:
                    edges.add((parent, child))
                    citations.setdefault((parent, child), []).append(str(req))
                else:
                    unresolved.append(dict(parent=parent, requirement=str(req)))
    return items, edges, unresolved, requirements, extras, citations


def sbom_facts(document):
    components = list(document.get("components", []))
    root = document.get("metadata", {}).get("component")
    if root:
        components.append(root)
    refs = {r["bom-ref"]: r for r in components}
    # Keep distinct records; projection onto installed scope happens separately.
    packages = [r for r in components if str(r.get("purl", "")).startswith("pkg:pypi/")]
    edges, dangling = set(), []
    for row in document.get("dependencies", []):
        for target in row.get("dependsOn", []):
            if row["ref"] in refs and target in refs:
                edges.add((canon(refs[row["ref"]]["name"]), canon(refs[target]["name"])))
            else:
                dangling.append((row["ref"], target))
    return components, packages, edges, dangling


def reach(root, edges):
    nodes = {root}
    while True:
        expanded = nodes | {b for a, b in edges if a in nodes}
        if expanded == nodes:
            return nodes
        nodes = expanded


def assess(case, directory, git_bindings=None):
    result = dict(case=case["id"], origin_commit=case["origin_commit"], source={})
    if case["kind"].startswith("cofano"):
        # Declared author test ingredients, not a guessed complete installed graph.
        required_names = {"numpy", "black", "docopt", "seaborn", "matplotlib", "urllib3"}
    else:
        required_names = None
    source_results = load(directory / "source-results.json")
    for tool, execution in source_results.items():
        path = directory / f"source-{tool}.cdx.json"
        record = dict(exit_code=execution.get("exit_code"), status=execution.get("status"))
        if path.exists() and path.stat().st_size and execution.get("exit_code") == 0:
            components, packages, edges, dangling = sbom_facts(load(path))
            names = {canon(p["name"]) for p in packages}
            record.update(python_names=sorted(names), python_package_records=len(packages),
                python_versions=[dict(name=p["name"], version=p.get("version")) for p in packages],
                all_dependency_edges=len(edges), dangling_references=dangling)
            if required_names is not None:
                record.update(author_ingredient_names_present=sorted(names & required_names),
                    author_ingredient_names_absent=sorted(required_names - names),
                    interpretation="Ingredient identity coverage only; not installed precision/recall")
        result["source"][tool] = record
    build = load(directory / "build-result.json") if (directory / "build-result.json").exists() else {"status": "PENDING"}
    result["build_status"] = build["status"]
    result["build_reason"] = build.get("reason")
    if build["status"] != "COMPLETE" or not (directory / "inventory.json").exists():
        return result
    seeds = {"requests": ["security"]} if case["id"].startswith("dsn/") else {}
    inventory = load(directory / "inventory.json")
    installed, expected, unresolved, requirements, extras, citations = declaration_graph(inventory, seeds, git_bindings)
    result.update(installed_packages=len(installed), declared_active_edges=len(expected),
        unresolved_declarations=unresolved, requested_extra_seeds=seeds,
        active_extras={n: sorted(v) for n, v in extras.items() if v}, installed={})
    if case["kind"] == "dsn":
        root_name = None
    else:
        p = Path(case["source"]) / "pyproject.toml"
        data = tomllib.loads(p.read_text()) if p.exists() else {}
        root_name = canon(data.get("project", {}).get("name") or data.get("tool", {}).get("poetry", {}).get("name")
                          or {"python-fire": "fire"}.get(directory.name, directory.name))
    result["root_name"] = root_name
    result["root_declared_active_edges"] = sorted(e for e in expected if e[0] == root_name)
    for filename in ("environment.cdx.json", "environment-pyproject.cdx.json", "installed-syft.cdx.json", "installed-trivy.cdx.json"):
        path = directory / filename
        label = filename.removesuffix(".cdx.json")
        execution = load(directory / (label + ".execution.json")) if (directory / (label + ".execution.json")).exists() else None
        if not execution or execution["exit_code"]:
            result["installed"][label] = {"status": "FAILED_OR_UNAVAILABLE", "exit_code": execution and execution["exit_code"]}
            continue
        components, packages, raw_edges, dangling = sbom_facts(load(path))
        # Name-level topology is reported separately from exact identity fidelity.
        projected = {e for e in raw_edges if e[0] in installed and e[1] in installed}
        missing, extra = expected - projected, projected - expected
        unresolved_parents = {r["parent"] for r in unresolved}
        known_extra = {e for e in extra if e[0] not in unresolved_parents}
        explanations = []
        for a, b in sorted(known_extra):
            matches = [r for r in requirements[a] if canon(r.name) == b]
            inactive = bool(matches) and all(r.marker is not None and all(not r.marker.evaluate(
                environment={**inventory["environment"], "extra": e}) for e in {"", *extras[a]}) for r in matches)
            explanations.append(dict(source=a, target=b, declarations=[str(r) for r in matches],
                mechanism="INACTIVE_MARKER_OR_EXTRA" if inactive else "NO_DECLARATION" if not matches else "REVIEW"))
        observed_names = {canon(c["name"]) for c in components}
        unknown_versions = sorted({canon(c["name"]) for c in components if canon(c["name"]) in installed and not c.get("version")})
        wrong_versions = [dict(name=canon(c["name"]), observed=c["version"], installed=installed[canon(c["name"])]["version"])
            for c in components if canon(c["name"]) in installed and c.get("version") and c["version"] != installed[canon(c["name"])]["version"]]
        result["installed"][label] = dict(status="COMPLETE", projected_edges=len(projected), missing_edges=sorted(missing),
            missing_edge_citations=[dict(source=a, target=b, declarations=citations[a, b]) for a, b in sorted(missing)],
            known_extra_edges=sorted(known_extra), unresolved_extra_edges=sorted(extra - known_extra),
            extra_explanations=explanations, absent_installed_names=sorted(set(installed) - observed_names),
            unknown_installed_versions=unknown_versions, version_mismatches=wrong_versions, dangling_references=dangling,
            root_missing_edges=sorted(e for e in missing if e[0] == root_name),
            missed_reachable_names=sorted(reach(root_name, expected) - reach(root_name, projected)) if root_name else None,
            unexpected_reachable_names=sorted(reach(root_name, projected) - reach(root_name, expected)) if root_name else None,
            metric_scope="Name-level projection onto observed installed inventory; version fidelity reported separately")
    return result


def main(out):
    out = Path(out)
    plan = load(out / "plan.json")
    bindings = load(out / "git-revisions.json") if (out / "git-revisions.json").exists() else {}
    records = []
    for case in plan["cases"]:
        directory = out / case["id"]
        result = assess(case, directory, bindings)
        save(directory / "assessment.json", result)
        records.append(result)
    summary = dict(cases=len(records), corpora=dict(Counter(r["case"].split("/")[0] for r in records)),
        build_statuses=dict(Counter(r["build_status"] for r in records)), records=records,
        claim="Exploratory paper-corpus probes, not historical reproduction, independent correctness proof or novelty evidence")
    save(out / "summary.json", summary)
    for r in records:
        tools = {k: dict(missing=len(v.get("missing_edges", [])), extra=len(v.get("known_extra_edges", [])))
                 for k, v in r.get("installed", {}).items() if v.get("status") == "COMPLETE"}
        print(r["case"], r["build_status"], tools)


if __name__ == "__main__":
    main(sys.argv[1])
