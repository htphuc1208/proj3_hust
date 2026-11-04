"""Trusted benchmark preparation, deliberately excluded from prediction workers.

This adapter turns the independently captured installed graph into a native SPDX
observation *before* controlled masking. It is never an evidence source, a
candidate enumerator, or a registry seed list. Only the masked observation is
passed to reconstruction; the full reference and removal log remain outside.
"""
from datetime import datetime
from packaging.utils import canonicalize_name

from sbom_recovery.formats import canonical_purl, sha


def reference_spdx(reference, field_labels, root_purls, created):
    datetime.fromisoformat(created.replace("Z", "+00:00"))
    identities, packages, index = {}, [], {}
    for node in sorted(reference["nodes"], key=lambda n: n["purl"]):
        name = canonicalize_name(node["name"])
        purl = canonical_purl(node["purl"])
        if name in index or purl in identities:
            raise ValueError("Independent installed reference has duplicate identities")
        label = field_labels.get(name, {})
        if label.get("version", node["version"]) != node["version"] or canonical_purl(label.get("purl", purl)) != purl:
            raise ValueError("Independent graph and field labels disagree")
        ref = "SPDXRef-Package-" + sha(purl)
        identities[purl] = ref
        index[name] = ref
        item = {"SPDXID": ref, "name": name, "versionInfo": node["version"],
                "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}]}
        if "licenseDeclared" in label:
            item["licenseDeclared"] = label["licenseDeclared"]
        packages.append(item)
    relationships = []
    for edge in reference["edges"]:
        parent, child = canonicalize_name(edge["from"]), canonicalize_name(edge["to"])
        if parent not in index or child not in index:
            raise ValueError("Independent reference contains a dangling dependency")
        relationships.append({"spdxElementId": index[parent], "relatedSpdxElement": index[child], "relationshipType": "DEPENDS_ON"})
    for purl in sorted(set(root_purls)):
        canonical = canonical_purl(purl)
        if canonical not in identities:
            raise ValueError("Predeclared application root is absent from the independent reference")
        relationships.append({"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": identities[canonical], "relationshipType": "DESCRIBES"})
    document = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Controlled installed reference: " + reference["project"],
        "documentNamespace": "https://sbom-recovery.local/controlled/" + sha(reference),
        "creationInfo": {"creators": ["Tool: independent-installed-reference-adapter-v1"], "created": created},
        "packages": packages, "relationships": sorted(relationships, key=lambda r: tuple(r.values()))}
    return document


def masked_reference(capture_dir, root_purls, family, rate, seed):
    """Trusted input generation; never call this from an evidence collector."""
    from pathlib import Path
    from research_core import load, digest
    from sbom_recovery.formats import validate_native
    from sbom_recovery.metrics import controlled_mask
    root = Path(capture_dir)
    graph = root / "oracle/installed_reference.json"
    fields = root / "oracle/installed_field_labels.json"
    capture = load(root / "capture.json")
    created = datetime.fromisoformat(capture["completed_at"].replace("Z", "+00:00")).strftime("%Y-%m-%dT%H:%M:%SZ")
    document = reference_spdx(load(graph), load(fields)["fields"], root_purls, created)
    validity = validate_native(document)
    if not validity["valid"]:
        raise ValueError("Independent controlled input is structurally invalid")
    masked, log = controlled_mask(document, rate, seed, family)
    provenance = {"input_origin": "INDEPENDENT_REFERENCE_MASK", "reference_graph_sha256": digest(graph),
        "field_labels_sha256": digest(fields), "adapter_sha256": digest(__file__),
        "unmasked_input_sha256": sha(document), "masked_input_sha256": sha(masked),
        "oracle_use": "Trusted masking before prediction; scoring after sealing",
        "oracle_exposed_to_prediction_worker": False,
        "unmasked_reference_in_evidence_store": False}
    return masked, log, provenance
