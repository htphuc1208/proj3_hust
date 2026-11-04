"""Auditable, oracle-free SBOM normalization and versioned run artifacts.

Scope decisions describe evidence, not runtime use. Only the scorer reads labels.
"""
from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import uuid
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from packaging.utils import canonicalize_name
from resolver import normalize_purl

PROTOCOL = "m2.3-validation-v1"
ROOT = Path(__file__).resolve().parent


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False,
                               default=lambda x: sorted(x) if isinstance(x, set) else str(x)) + "\n")


def load(path):
    return json.loads(Path(path).read_text())


def components(sbom):
    root = sbom.get("metadata", {}).get("component")
    return ([root] if root else []) + sbom.get("components", [])


def graph(sbom):
    refs = {c.get("bom-ref"): normalize_purl(c["purl"]) for c in components(sbom) if c.get("purl")}
    return set(refs.values()), {(refs[d["ref"]], refs[t]) for d in sbom.get("dependencies", [])
                                for t in d.get("dependsOn", []) if d.get("ref") in refs and t in refs}


def normalize_sbom(raw, root_name=None, bootstrap=()):
    """No oracle argument, installation metadata, or filesystem discovery is used.

    bootstrap is a declared provisioning context, not a universal package blacklist.
    Bootstrap distributions stay in the normalized input; only scoring projects scope.
    """
    audit, eligible, refmap = [], {}, {}
    bootstrap = {canonicalize_name(n) for n in bootstrap}
    for index, component in enumerate(components(raw)):
        c = deepcopy(component)
        ref = c.get("bom-ref", f"unreferenced:{index}")
        locations = [p.get("value", "") for p in c.get("properties", []) if "location" in p.get("name", "")]
        props = {p.get("name"): p.get("value") for p in c.get("properties", [])}
        name, purl = canonicalize_name(c.get("name", "")), c.get("purl", "")
        kind, role, reason = "UNKNOWN", "UNKNOWN", "Insufficient distribution identity evidence"
        if any("/_vendor/" in p.replace("\\", "/") or "/vendored/" in p for p in locations):
            kind, reason = "VENDORED", "Scanner origin path is inside a vendored directory"
        elif c.get("type") == "file":
            kind, reason = "FILE", "Raw CycloneDX component type=file"
        elif purl.startswith("pkg:pypi/") and "@" in purl and c.get("version"):
            kind, reason = "DISTRIBUTION_CANDIDATE", "Versioned PyPI PURL supplied by generator"
            if props.get("syft:package:foundBy") == "python-installed-package-cataloger":
                reason += "; installed-package cataloger and distribution paths"
            role = "BOOTSTRAP" if name in bootstrap else "UNKNOWN"
            if root_name and name == canonicalize_name(root_name):
                role = "DECLARED_ROOT"
            norm = normalize_purl(purl)
            refmap[ref] = norm
            # Every original occurrence remains auditable even when normalized identities coincide.
            eligible.setdefault(norm, {"type": "library", "name": name, "version": c["version"],
                                       "purl": norm, "bom-ref": norm})
        elif c.get("type") == "application":
            kind, reason = "ARTIFACT", "Non-PyPI application/binary component"
        audit.append({"original_ref": ref, "canonical_identity": refmap.get(ref, ""),
                      "name": c.get("name", ""), "version": c.get("version", ""),
                      "component_type": c.get("type", ""), "origin_paths": locations,
                      "artifact_kind": kind, "role": role, "classification_evidence": reason,
                      "retained_for_inference": ref in refmap})
    matches = [c for c in eligible.values() if root_name and c["name"] == canonicalize_name(root_name)]
    metadata = {}
    if len(matches) == 1:
        root = deepcopy(matches[0])
        root["type"] = "application"
        metadata["component"] = root
    else:
        root = None  # Do not invent a root/version or choose an arbitrary first component.
    out = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "metadata": metadata,
           "components": [c for c in eligible.values() if not root or c["purl"] != root["purl"]]}
    edge_audit, deps = [], {}
    if "dependencies" in raw:
        for declaration in raw["dependencies"]:
            source = declaration.get("ref")
            if source in refmap:
                deps.setdefault(refmap[source], set())
            for target in declaration.get("dependsOn", []):
                retained = source in refmap and target in refmap
                if retained:
                    deps[refmap[source]].add(refmap[target])
                edge_audit.append({"source_original_ref": source, "target_original_ref": target,
                                   "source": refmap.get(source), "target": refmap.get(target),
                                   "decision": "RETAINED" if retained else "INVENTORY_OR_UNRESOLVED_REFERENCE"})
        out["dependencies"] = [{"ref": r, "dependsOn": sorted(ts)} for r, ts in sorted(deps.items())]
    return out, {"schema_version": "scope-audit-v1", "components": audit, "edges": edge_audit,
                 "root_status": "OBSERVED_DECLARED_ROOT" if root else "ROOT_UNKNOWN",
                 "counts": dict(Counter(c["artifact_kind"] for c in audit)),
                 "bootstrap_context": sorted(bootstrap)}


def export_scope_csv(path, records):
    fields = ["project", "generator", "original_ref", "canonical_identity", "name", "version",
              "component_type", "origin_paths", "artifact_kind", "role", "classification_evidence",
              "retained_for_inference"]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for row in records:
            writer.writerow({k: json.dumps(row[k]) if isinstance(row.get(k), list) else row.get(k) for k in fields})


def score_sets(truth, prediction):
    tp, fp, fn = len(truth & prediction), len(prediction - truth), len(truth - prediction)
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None}


def score_application(gold, observed, predicted, scope):
    """Oracle is used exclusively here. Never use a truth intersection to prune FPs."""
    refs = {n["name"]: normalize_purl(n["purl"]) for n in gold["nodes"]}
    truth = {(refs[e["from"]], refs[e["to"]]) for e in gold["edges"]}
    role = {c["canonical_identity"]: c["role"] for c in scope["components"] if c["canonical_identity"]}
    uncertain_parents = {refs[u["parent"]] for u in gold.get("unresolved", []) if u.get("parent") in refs}
    audit = []

    def project(edges, arm):
        retained = set()
        for source, target in sorted(edges):
            if source in uncertain_parents and (source, target) not in truth:
                decision = "UNKNOWN_LABEL"
            elif role.get(source) == "BOOTSTRAP" and source not in refs.values():
                decision = "EXCLUDED_BOOTSTRAP_SOURCE"
            else:
                decision = "SCORED_TP" if (source, target) in truth else "SCORED_FP"
                retained.add((source, target))
            audit.append({"arm": arm, "source": source, "target": target, "decision": decision})
        return retained

    obs, pred = project(observed, "observed"), project(predicted, "predicted")
    return {"whole_graph": score_sets(truth, pred),
            "additions": score_sets(truth - obs, pred - obs),
            "recovered_edges": sorted((pred - obs) & truth), "false_positive_edges": sorted(pred - truth),
            "missed_edges": sorted(truth - pred), "edge_audit": audit,
            "reference_nodes": len(refs), "reference_edges": len(truth),
            "unresolved_reference_requirements": gold.get("unresolved", []),
            "excluded_or_unknown_edges": sum(not a["decision"].startswith("SCORED") for a in audit)}


def validate_cdx(document, schema_dir=None):
    from jsonschema import Draft7Validator, FormatChecker
    from referencing import Registry, Resource
    folder = Path(schema_dir or ROOT / "research/schemas")
    resources = []
    for path in folder.glob("*.schema.json"):
        schema = load(path)
        resource = Resource.from_contents(schema, default_specification=__import__("referencing.jsonschema", fromlist=["DRAFT7"]).DRAFT7)
        for uri in (schema.get("$id", ""), "http://cyclonedx.org/schema/" + path.name,
                    "https://cyclonedx.org/schema/" + path.name):
            if uri:
                resources.append((uri, resource))
    schema_file = folder / f"bom-{document.get('specVersion', '1.5')}.schema.json"
    validator = Draft7Validator(load(schema_file), registry=Registry().with_resources(resources), format_checker=FormatChecker())
    errors = [{"path": list(e.absolute_path), "message": e.message} for e in validator.iter_errors(document)]
    refs = [c.get("bom-ref") for c in components(document) if c.get("bom-ref")]
    if len(refs) != len(set(refs)):
        errors.append({"path": [], "message": "Duplicate component bom-ref"})
    for d in document.get("dependencies", []):
        for ref in [d.get("ref")] + d.get("dependsOn", []):
            if ref not in refs:
                errors.append({"path": ["dependencies"], "message": f"Unresolved component reference: {ref}"})
    return {"valid": not errors, "schema": schema_file.name, "schema_sha256": digest(schema_file), "errors": errors}


class RunBundle:
    def __init__(self, out, run_id, **context):
        self.out = Path(out)
        self.out.mkdir(parents=True, exist_ok=False)
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        self.data = {"schema_version": "run-manifest-v1", "protocol": PROTOCOL, "run_id": run_id,
                     "source_commit": commit, "started_at": now(), "status": "RUNNING", "stages": {},
                     "artifacts": {}, "context": context}
        self.data["source_code_sha256"] = {str(p.relative_to(ROOT)): digest(p)
            for p in sorted(list(ROOT.glob("*.py")) + list((ROOT / "scripts").glob("*.py")))}
        self.flush()

    def flush(self):
        save(self.out / "run_manifest.json", self.data)

    def artifact(self, name, value):
        save(self.out / name, value)
        self.data["artifacts"][name] = {"sha256": digest(self.out / name), "written_at": now()}
        self.flush()

    def copy(self, name, source):
        (self.out / name).parent.mkdir(parents=True, exist_ok=True)
        (self.out / name).write_bytes(Path(source).read_bytes())
        self.data["artifacts"][name] = {"sha256": digest(self.out / name), "written_at": now(), "source": str(source)}
        self.flush()

    def finish(self, status="COMPLETE", **details):
        self.data.update(status=status, completed_at=now(), **details)
        self.flush()


def reconstructed_document(sbom):
    document = deepcopy(sbom)
    document["serialNumber"] = "urn:uuid:" + str(uuid.uuid4())
    document["version"] = 1
    document.setdefault("metadata", {})["timestamp"] = now()
    document["metadata"].setdefault("properties", []).append(
        {"name": "reconstruction:interpretation", "value": "Candidate graph; no installed-artifact or exploitability assertion"})
    return document
