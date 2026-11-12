#!/usr/bin/env python3
"""Export multi-SBOM input schema and synthetic observations, not a merger."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sbom_recovery.reconciliation.merge_contracts_v3 import ReconciliationRequestV3


def write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def main():
    folder = ROOT / "research/design/reconciliation-v3"
    schema = ReconciliationRequestV3.model_json_schema()
    schema.update({"$schema":"https://json-schema.org/draft/2020-12/schema", "$id":"urn:sbom-recovery:reconciliation-v3:input"})
    write(folder / "schemas/input.schema.json", schema)
    sources = []
    for label, version in [("a", "2.1.0"), ("b", "2.0.9")]:
        document = dict(bomFormat="CycloneDX", specVersion="1.6", version=1,
            metadata=dict(component=dict(type="application", name="design-app", version="1", **{"bom-ref":"app"})),
            components=[dict(type="library", name="design-lib", version=version, purl="pkg:npm/design-lib@" + version,
                             **{"bom-ref":"dependency"})],
            dependencies=[dict(ref="app", dependsOn=["dependency"])])
        relative = "inputs/tool-" + label + ".cdx.json"
        write(folder / "examples" / relative, document)
        digest = hashlib.sha256((folder / "examples" / relative).read_bytes()).hexdigest()
        sources.append(dict(source_id="tool-" + label, document=dict(path=relative, sha256=digest), format="CycloneDX",
            producer=dict(name="synthetic-design-tool-" + label, version="0"), target_id="design-release",
            revision_ref="fixture-v1", context_id="ctx-linux", view="RESOLVED"))
    request = dict(target=dict(target_id="design-release", project_ref="design-example",
        revision_ref="fixture-v1", context=dict(context_id="ctx-linux", os="linux", architecture="amd64",
        runtimes={"node":"22"}, features_by_subject={"application":None}), view="RESOLVED"),
        documents=sources, evidence=[], policy_id="abe-design-v3")
    write(folder / "examples/input.json", ReconciliationRequestV3.model_validate(request).model_dump(mode="json"))
    print("Exported multi-SBOM schema and synthetic request/documents; no merge or correctness claim")


if __name__ == "__main__":
    main()
