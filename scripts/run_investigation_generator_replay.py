"""Replay previously captured native npm generator outputs without labels/network.

The source subject is a controlled alias fixture. This checks compatibility with
actual tool outputs; it is not an independently adjudicated real-project pilot.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    from sbom_recovery.investigation.runner import investigate, save_run
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", default=str(ROOT / "runs/cross-ecosystem-probe-v1/npm-alias"))
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    capture, output = Path(args.capture), Path(args.out)
    manifest = json.loads((capture / "input-manifest.json").read_text())
    lock = (capture / "input/package-lock.json").read_bytes()
    if hashlib.sha256(lock).hexdigest() != manifest["files"]["package-lock.json"]:
        raise ValueError("Captured lockfile no longer matches its source manifest")
    output.mkdir(parents=True, exist_ok=False)
    bundle = output / "public"
    bundle.mkdir()
    def freeze(name, raw):
        (bundle / name).write_bytes(raw)
        return {"path": name, "sha256": hashlib.sha256(raw).hexdigest()}
    target = {"target_id": "captured-npm-alias", "revision_ref": "source-manifest:" +
        hashlib.sha256((capture / "input-manifest.json").read_bytes()).hexdigest(),
        "context_id": "all-dependencies-linux", "view": "RESOLVED"}
    documents = []
    records = []
    for filename, execution in (("npm-all.cdx.json", "npm-sbom-all.execution.json"),
                                ("cyclonedx-npm-all.cdx.json", "cyclonedx-npm-all.execution.json")):
        record = json.loads((capture / execution).read_text())
        if record["exit_code"] != 0 or record["cwd"] != manifest["source"]:
            raise ValueError("Generator execution does not match the captured source")
        native = json.loads((capture / filename).read_text())
        tools = native.get("metadata", {}).get("tools", {})
        records.append({"file": filename, "execution": record, "native_tools": tools})
        documents.append({"source_id": filename.split(".")[0], "document": freeze(filename, (capture / filename).read_bytes()),
            "format": "CycloneDX", "producer": {"name": record["command"][0]}, **target})
    envelope = {"schema_version": "native-evidence-v1", "target": target, "format": "npm-lock", "data": json.loads(lock)}
    blob = freeze("lock-evidence.json", (json.dumps(envelope, indent=2) + "\n").encode())
    request = {"schema_version": "sbom-reconciliation-input-v3", "policy_id": "native-generator-replay-v1",
        "target": {"target_id": target["target_id"], "project_ref": "controlled-npm-alias",
                   "revision_ref": target["revision_ref"], "context": {"context_id": target["context_id"], "os": "linux"}, "view": target["view"]},
        "documents": documents, "evidence": [{"source_id": "resolved-lock", "kind": "lockfile", "blob": blob}]}
    (bundle / "request.json").write_text(json.dumps(request, indent=2) + "\n")
    result = save_run(investigate(request, bundle), output / "prediction")
    verification = {"schema_version": "generator-replay-verification-v1", "result": result, "generator_executions": records,
        "input_manifest_sha256": hashlib.sha256((capture / "input-manifest.json").read_bytes()).hexdigest(),
        "reference_labels_read": False, "independent_correctness": "NOT_SCORED",
        "interpretation": "Native-generator compatibility replay on an existing controlled subject; not a fresh real-project pilot"}
    (output / "verification.json").write_text(json.dumps(verification, indent=2) + "\n")
    print(json.dumps({**result, "verification": str(output / "verification.json")}, indent=2))


if __name__ == "__main__":
    main()
