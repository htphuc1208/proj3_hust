#!/usr/bin/env python3
"""Export draft contracts and synthetic wire examples; does not inspect an artifact."""
from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sbom_recovery.reconciliation.contracts_v3 import ArtifactRequestV3, ArtifactAssessmentV3

ARTIFACT = "a" * 64
SBOM = "b" * 64


def scope(domain="package_identity", phase="ARTIFACT"):
    return dict(target_sha256=ARTIFACT, phase=phase, unit_domain=domain,
                context_id="ctx-example" if phase == "RESOLVED" else None)


def candidate(version):
    return dict(candidate_id="identity:text:" + version, ecosystem="maven", namespace="org.example",
                name="text", version=version, purl="pkg:maven/org.example/text@" + version)


def claim(claim_id, predicate, status, *, obj=True, domain="code_footprint", phase="ARTIFACT"):
    value = dict(claim_id=claim_id, subject="occ:text", predicate=predicate, object=obj,
                 scope=scope(domain, phase), status=status, rule_id="design-example." + predicate,
                 reason="Synthetic contract example, not an observed execution")
    if status in {"SUPPORTED", "CONFLICT"}:
        value["support_evidence_ids"] = ["source:artifact"]
    if status in {"REFUTED", "CONFLICT"}:
        value["refutation_evidence_ids"] = ["source:second-observation"]
    return value


def examples():
    target = dict(artifact=dict(path="artifacts/example.jar", sha256=ARTIFACT), kind="java_jar")
    context = dict(context_id="ctx-example", os=None, architecture=None, runtimes={"java":None},
                   features_by_subject={"application":[], "optional-library":None})
    request = dict(target=target, sbom=dict(path="input.cdx.json", sha256=SBOM), sbom_format="CycloneDX",
                   context=context, policy_id="artifact-v3-design-draft", evidence=[])
    source = dict(source_id="source:artifact", blob=target["artifact"], kind="artifact_bytes",
                  binding="DIRECT_ARTIFACT", observed_target_sha256=ARTIFACT)
    base = dict(target=target, input_sbom_sha256=SBOM, context=context,
                policy_id=request["policy_id"], evidence=[source], candidates=[candidate("1.9")],
                bindings=[dict(binding_id="binding:text", occurrence_id="occ:text", scope=scope(),
                               candidate_ids=["identity:text:1.9"], resolution="UNIQUE", basis="TARGET_METADATA",
                               evidence_ids=["source:artifact"])],
                claims=[claim("claim:identity", "identity", "SUPPORTED", obj="identity:text:1.9", domain="package_identity"),
                        claim("claim:metadata", "metadata_present", "SUPPORTED"),
                        claim("claim:code", "code_present", "UNKNOWN")],
                issues=["Synthetic wire example; files/digests are placeholders and were not collected from a release"])
    supported = deepcopy(base)
    supported["changes"] = [dict(change_id="change:add-text", operation="ADD_COMPONENT", disposition="APPLY",
        scope=scope(), subject="occ:text", claim_ids=["claim:identity", "claim:metadata"],
        binding_ids=["binding:text"], before=None,
        after=dict(name="text", version="1.9", purl="pkg:maven/org.example/text@1.9"),
        rule_id="design-example.add-bound-component", reason="Target-bound identity and metadata occurrence")]
    metadata_only = deepcopy(base)
    second = deepcopy(source)
    second["source_id"] = "source:second-observation"
    metadata_only["evidence"].append(second)
    metadata_only["coverage"] = [dict(coverage_id="coverage:code", scope=scope("code_footprint"),
        status="COMPLETE", evidence_ids=["source:artifact"], identity_mapping_complete=True)]
    metadata_only["claims"][2] = claim("claim:code", "code_present", "REFUTED")
    metadata_only["claims"][2]["refutation_coverage_ids"] = ["coverage:code"]
    native = dict(source_id="source:build", blob=dict(path="evidence/native-tree.json", sha256="c"*64),
        kind="native_resolution", binding="MATCHED_OUTPUT", observed_target_sha256=ARTIFACT)
    metadata_only["evidence"].append(native)
    selected = claim("claim:selected", "selected", "SUPPORTED", domain="selected_dependency", phase="RESOLVED")
    selected["support_evidence_ids"] = ["source:build"]
    metadata_only["claims"].append(selected)
    ambiguous = deepcopy(base)
    ambiguous["candidates"].append(candidate("2.0"))
    ambiguous["bindings"][0].update(candidate_ids=["identity:text:1.9", "identity:text:2.0"],
                                     resolution="AMBIGUOUS", basis="PARTIAL_FINGERPRINT")
    ambiguous["claims"][0] = claim("claim:identity", "identity", "UNKNOWN", obj="identity:text:1.9", domain="package_identity")
    ambiguous["changes"] = [deepcopy(supported["changes"][0])]
    ambiguous["changes"][0].update(disposition="DEFER", reason="Partial fingerprint cannot select one release")
    conflict = deepcopy(ambiguous)
    conflict["evidence"].append(second)
    conflict["bindings"][0]["resolution"] = "CONFLICT"
    conflict["claims"][0] = claim("claim:identity", "identity", "CONFLICT", obj="identity:text:1.9", domain="package_identity")
    conflict["changes"][0]["reason"] = "Incompatible identity observations in the same target scope"
    return request, {"supported-component":supported, "metadata-only":metadata_only,
                     "ambiguous-identity":ambiguous, "conflicting-identity":conflict}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def main():
    folder = ROOT / "research/design/artifact-reconciliation-v3"
    for name, model in [("input", ArtifactRequestV3), ("assessment", ArtifactAssessmentV3)]:
        schema = model.model_json_schema()
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = "urn:sbom-recovery:artifact-reconciliation-v3:" + name
        write(folder / "schemas" / (name + ".schema.json"), schema)
    request, results = examples()
    write(folder / "examples/input.json", ArtifactRequestV3.model_validate(request).model_dump(mode="json"))
    for name, result in results.items():
        write(folder / "examples" / (name + ".assessment.json"), ArtifactAssessmentV3.model_validate(result).model_dump(mode="json"))
    print("Exported 2 schemas and 5 synthetic wire examples; no artifact inspection performed")


if __name__ == "__main__":
    main()
