#!/usr/bin/env python3
"""Reproducible masks + evaluation for a CycloneDX SBOM.

Run with Python standard library. Input full SBOM is a *reference graph*,
not universal truth about which dependencies ship in another environment.
"""
import argparse
import json
import random
from copy import deepcopy
from pathlib import Path


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def dump(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def items(sbom):
    out = []
    root = sbom.get("metadata", {}).get("component")
    if isinstance(root, dict) and root.get("bom-ref"):
        out.append(root)
    out.extend(c for c in sbom.get("components", []) if c.get("bom-ref"))
    return out


def id_for(component):
    # Compare graph across changed bom-refs using package identities when present.
    # Intentionally only a minimal normalizer; PURL parser is a next improvement.
    purl = component.get("purl", "")
    if purl:
        purl = purl.split("?", 1)[0].split("#", 1)[0]
        if purl.lower().startswith("pkg:pypi/") and "@" in purl:
            name, version = purl[9:].rsplit("@", 1)
            name = name.lower().replace("_", "-").replace(".", "-")
            purl = "pkg:pypi/" + name + "@" + version
        return purl
    return "bom-ref:" + component["bom-ref"]


def extract(sbom):
    refs = {}
    for c in items(sbom):
        ident = id_for(c)
        ref = c["bom-ref"]
        if ref in refs and refs[ref] != ident:
            raise ValueError("Conflicting component reference: " + ref)
        refs[ref] = ident
    nodes = set(refs.values())
    edges = set()
    dangling = 0
    for dep in sbom.get("dependencies", []):
        source = refs.get(dep.get("ref"))
        for target_ref in dep.get("dependsOn", []):
            target = refs.get(target_ref)
            if source and target:
                edges.add((source, target))
            else:
                dangling += 1
    return nodes, edges, dangling


def cmd_mask(args):
    if not 0 <= args.drop_node <= 1 or not 0 <= args.drop_source <= 1:
        raise ValueError("Probabilities must be in [0,1]")
    sbom = load(args.truth)
    nodes, edges, dangling = extract(sbom)
    if not edges:
        raise ValueError("Reference SBOM has no usable dependency edges")
    rng = random.Random(args.seed)
    out = deepcopy(sbom)
    root_ref = sbom.get("metadata", {}).get("component", {}).get("bom-ref")
    removed_nodes = {
        c["bom-ref"] for c in sbom.get("components", [])
        if c.get("bom-ref") and rng.random() < args.drop_node
    }
    out["components"] = [
        c for c in sbom.get("components", []) if c.get("bom-ref") not in removed_nodes
    ]
    # The current baseline treats any explicit dependsOn declaration as complete.
    # Delete whole source declarations, never silently truncate an explicit list.
    removed_sources = set()
    kept_dependencies = []
    for dep in sbom.get("dependencies", []):
        src = dep.get("ref")
        touches_deleted_node = src in removed_nodes or any(
            target in removed_nodes for target in dep.get("dependsOn", [])
        )
        if touches_deleted_node or rng.random() < args.drop_source:
            removed_sources.add(src)
        else:
            kept_dependencies.append(dep)
    out["dependencies"] = kept_dependencies
    out.setdefault("metadata", {}).setdefault("properties", []).append({
        "name": "experiment:synthetic-incompleteness", "value": "true"
    })
    dump(args.out, out)
    observed_nodes, observed_edges, _ = extract(out)
    stats = {
        "warning": "Synthetic masking: NOT real generator omissions; reference is environment-specific",
        "seed": args.seed, "drop_node_probability": args.drop_node,
        "drop_source_probability": args.drop_source,
        "reference_nodes": len(nodes), "reference_edges": len(edges),
        "observed_nodes": len(observed_nodes), "observed_edges": len(observed_edges),
        "actually_missing_nodes": len(nodes - observed_nodes),
        "actually_missing_edges": len(edges - observed_edges),
        "removed_dependency_declarations": len(removed_sources),
        "ignored_dangling_reference_edges": dangling,
    }
    dump(args.summary, stats)
    print(json.dumps(stats, indent=2, ensure_ascii=False))
    print("Masked SBOM:", args.out)


def prf(tp, fp, fn):
    # None = undefined, as opposed to pretending no predictions have precision=1.
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * tp / (2 * tp + fp + fn)) if (2 * tp + fp + fn) else None
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1}


def score(gold, obs, pred):
    missing = gold - obs
    new_predictions = pred - obs
    tp = len(missing & new_predictions)
    return prf(tp, len(new_predictions - gold), len(missing - new_predictions))


def cmd_score(args):
    gt_nodes, gt_edges, gt_dangling = extract(load(args.truth))
    ob_nodes, ob_edges, ob_dangling = extract(load(args.input))
    pd_nodes, pd_edges, pd_dangling = extract(load(args.pred))
    if not (ob_nodes <= gt_nodes and ob_edges <= gt_edges):
        raise ValueError("Input SBOM is not a strict subset of reference; cannot interpret missing-edge recall")
    result = {
        "reference": {"nodes": len(gt_nodes), "edges": len(gt_edges), "dangling_edges": gt_dangling},
        "observed": {"nodes": len(ob_nodes), "edges": len(ob_edges), "dangling_edges": ob_dangling},
        "reconstructed": {"nodes": len(pd_nodes), "edges": len(pd_edges), "dangling_edges": pd_dangling},
        "new_component_recovery": score(gt_nodes, ob_nodes, pd_nodes),
        "new_edge_recovery": score(gt_edges, ob_edges, pd_edges),
        "warning": "Scores relative to provided reference, not evidence of performance on unseen real SBOMs"
    }
    dump(args.out, result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print("Scores:", args.out)


def main():
    p = argparse.ArgumentParser(description="CycloneDX missing node/edge experiment")
    commands = p.add_subparsers(dest="command", required=True)
    m = commands.add_parser("mask", help="Delete nodes and complete dependency declarations")
    m.add_argument("--truth", type=Path, required=True)
    m.add_argument("--drop-node", type=float, default=0.2)
    m.add_argument("--drop-source", type=float, default=0.5)
    m.add_argument("--seed", type=int, default=42)
    m.add_argument("--out", type=Path, default=Path("experiment/incomplete.cdx.json"))
    m.add_argument("--summary", type=Path, default=Path("experiment/masking_summary.json"))
    m.set_defaults(func=cmd_mask)
    s = commands.add_parser("score", help="Evaluate only newly predicted nodes and edges")
    s.add_argument("--truth", type=Path, required=True)
    s.add_argument("--input", type=Path, required=True)
    s.add_argument("--pred", type=Path, required=True)
    s.add_argument("--out", type=Path, default=Path("experiment/scores.json"))
    s.set_defaults(func=cmd_score)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
