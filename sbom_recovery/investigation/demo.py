"""Small controlled fixtures. These are not outputs of real SBOM generators."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def create_demo(destination):
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=False)
    def write(path, value):
        raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        path = root / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return {"path": str(path.relative_to(root)), "sha256": hashlib.sha256(raw).hexdigest()}
    cases = []
    for ecosystem in ("npm", "cargo"):
        prefix = ecosystem + "/"
        target = {"target_id": "demo-" + ecosystem, "revision_ref": "controlled-v1",
                  "context_id": "linux-runtime", "view": "RESOLVED"}
        def component(name, version, locator, ref, kind="library"):
            return {"type": kind, "bom-ref": ref, "name": name, "version": version,
                    "purl": "pkg:" + ecosystem + "/" + name + "@" + version,
                    "properties": [{"name": "sbom-recovery:locator", "value": locator}]}
        root_locator = "" if ecosystem == "npm" else "/workspace/demo/Cargo.toml"
        lib_locator = "node_modules/example-lib" if ecosystem == "npm" else "/registry/example-lib/Cargo.toml"
        root_id = "path+file:///workspace/demo#0.1.0"
        lib_id = "registry+https://github.com/rust-lang/crates.io-index#example-lib@1.4.3"
        docs = []
        for index, version in enumerate(("1.4.2", "1.4.3")):
            doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                   "metadata": {"component": component("demo", "0.1.0", root_locator, "app", "application")},
                   "components": [component("example-lib", version, lib_locator, "dependency")],
                   "dependencies": [{"ref": "app", "dependsOn": ["dependency"]}] if index == 0 else []}
            blob = write(prefix + "inputs/tool-" + str(index) + ".cdx.json", doc)
            docs.append({"source_id": "tool-" + str(index), "document": {**blob, "path": blob["path"][len(prefix):]},
                "format": "CycloneDX", "producer": {"name": "controlled-fixture-" + str(index), "version": "1"},
                **target})
        if ecosystem == "npm":
            native = {"name": "demo", "version": "0.1.0", "lockfileVersion": 3, "packages": {
                "": {"name": "demo", "version": "0.1.0", "dependencies": {"example-lib": "1.4.3"}},
                "node_modules/example-lib": {"version": "1.4.3"}}}
            fmt = "npm-lock"
        else:
            native = {"version": 1, "workspace_members": [root_id], "workspace_root": "/workspace/demo",
                "packages": [{"id": root_id, "name": "demo", "version": "0.1.0", "source": None,
                              "manifest_path": "/workspace/demo/Cargo.toml", "dependencies": []},
                             {"id": lib_id, "name": "example-lib", "version": "1.4.3",
                              "source": "registry+https://github.com/rust-lang/crates.io-index",
                              "manifest_path": "/registry/example-lib/Cargo.toml", "dependencies": []}],
                "resolve": {"root": root_id, "nodes": [
                    {"id": root_id, "deps": [{"name": "example_lib", "pkg": lib_id,
                     "dep_kinds": [{"kind": None, "target": None}]}], "dependencies": [lib_id], "features": []},
                    {"id": lib_id, "deps": [], "dependencies": [], "features": []}]}}
            fmt = "cargo-metadata"
        evidence = {"schema_version": "native-evidence-v1", "target": target, "format": fmt, "data": native}
        blob = write(prefix + "evidence/resolution.json", evidence)
        wrong = {**evidence, "target": {**target, "context_id": "different-context"}}
        decoy = write(prefix + "evidence/stale.json", wrong)
        request = {"schema_version": "sbom-reconciliation-input-v3", "target": {
            "target_id": target["target_id"], "project_ref": "controlled-demo-" + ecosystem,
            "revision_ref": target["revision_ref"], "context": {"context_id": target["context_id"], "os": "linux"},
            "view": "RESOLVED"}, "documents": docs, "policy_id": "eager-v3",
            "evidence": [{"source_id": name, "kind": "native_resolution", "blob": {
                **item, "path": item["path"][len(prefix):]}} for name, item in [("00-stale", decoy), ("01-resolution", blob)]]}
        req = write(prefix + "request.json", request)
        oracle = {"schema_version": "reconciliation-oracle-v1", "target": target, "components": [
            {"id": "gold-app", "ecosystem": ecosystem, "name": "demo", "version": "0.1.0", "locator": root_locator,
             "purl": "pkg:" + ecosystem + "/demo@0.1.0", "status": "SUPPORTED"},
            {"id": "gold-lib", "ecosystem": ecosystem, "name": "example-lib", "version": "1.4.3", "locator": lib_locator,
             "purl": "pkg:" + ecosystem + "/example-lib@1.4.3", "status": "SUPPORTED"}],
            "edges": [{"source": "gold-app", "target": "gold-lib", "relationship_type": "direct_dependency",
                       "scope": "runtime", "status": "SUPPORTED"}],
            "coverage": {"components": True, "edges": True, "paths": True},
            "roots": ["gold-app"], "label_protocol": "CONTROLLED_KNOWN_GRAPH_NOT_INDEPENDENT_REAL_WORLD_BUILD"}
        oracle_blob = write(prefix + "oracle/oracle.json", oracle)
        snapshot = {"schema_version": "osv-snapshot-v1", "advisories": [{"id": "DEMO-2026-001", "aliases": ["CVE-DEMO-001"],
            "affected": [{"package": {"ecosystem": "npm" if ecosystem == "npm" else "crates.io", "name": "example-lib"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.4.3"}]}]}]}],
            "provenance": "CONTROLLED_SYNTHETIC_ADVISORY"}
        snapshot_blob = write(prefix + "advisories.json", snapshot)
        write(prefix + "actions.json", [{"action": "acquire", "source_id": "00-stale"},
            {"action": "acquire", "source_id": "01-resolution"}, {"action": "finish"}])
        cases.append({"case_id": "controlled-" + ecosystem, "project": "demo-" + ecosystem,
                      "lineage": "demo-" + ecosystem, "split": "development", "request": req,
                      "oracle": oracle_blob, "snapshot": snapshot_blob})
    manifest = {"schema_version": "investigation-study-v1", "cases": cases,
                "methods": ["observed", "deterministic", "rule", "metadata_only", "graph_only"],
                "budget": {"max_tool_calls": 5}, "label_kind": "CONTROLLED_DEVELOPMENT_ONLY"}
    write("study.json", manifest)
    expanded = {**manifest, "methods": manifest["methods"] + ["naive_union", "fixed_priority", "majority",
        "lockfile_only", "single:tool-0", "single:tool-1", "sbom_unifier"],
        "conditions": ["equal_budget", "equal_information"]}
    write("study-baselines.json", expanded)
    return {"out": str(root), "cases": len(cases), "study_manifest": str(root / "study.json"),
            "interpretation": "Controlled smoke tests; no real-generator or agent-superiority claim"}
