"""Installed-metadata gate v2; receives acquired bytes only, never the full target.

Partial evidence never closes extras activation. Dynamic is informational for
these installed snapshots. Source-distribution metadata is not an accepted kind.
"""
from collections import Counter, defaultdict
from copy import deepcopy
from email.parser import BytesParser
import hashlib
import re

from packaging.requirements import Requirement, InvalidRequirement
from packaging.utils import canonicalize_name
from packaging.version import Version, InvalidVersion

from .formats import NativeDocument, sha
from .contracts import RepairProposal
from .budget_sources import validate_catalog, timestamp
from .reconciliation import bare_purl, identities, marker, activate_extras

POLICY = "acquired-installed-metadata-gate-v2"


def gate(document, context, catalog, acquired):
    validate_catalog(catalog, context)
    native = NativeDocument(document)
    sources = {row["source_id"]: row for row in catalog["sources"]}
    parsed, diagnostics = {}, []
    for source_id, raw in acquired.items():
        source = sources[source_id]
        if (hashlib.sha256(raw).hexdigest() != source["sha256"] or len(raw) != source["bytes"]
                or timestamp(source["available_at"]) > timestamp(context.evidence_cutoff)):
            raise ValueError("Acquired evidence digest/size/time mismatch")
        msg = BytesParser().parsebytes(raw)
        if source["kind"] != "installed_metadata":
            raise ValueError("Only installed metadata is eligible for this gate")
        try:
            if msg.defects or len(msg.get_all("Name", [])) != 1 or len(msg.get_all("Version", [])) != 1:
                raise ValueError("Invalid identity fields")
            name, version = canonicalize_name(msg["Name"]), msg["Version"]
            if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*",name):
                raise ValueError("Invalid distribution name")
            Version(version)
            purl = bare_purl(f"pkg:pypi/{name}@{version}")
            if name != source["name_hint"]:
                raise ValueError("Catalog filename and metadata identity disagree")
            requirements = [(text, Requirement(text)) for text in msg.get_all("Requires-Dist", [])]
            if purl in parsed:
                raise ValueError("Duplicate metadata identity")
        except (ValueError, InvalidVersion, InvalidRequirement):
            diagnostics.append({"source_id": source_id, "reason": "INVALID_OR_AMBIGUOUS_METADATA"})
            continue
        parsed[purl] = {"purl": purl, "name": name, "version": version, "requirements": requirements,
                        "source_id": source_id, "path": source["path"], "sha256": source["sha256"],
                        "dynamic_information": msg.get_all("Dynamic", [])}
    by_name = defaultdict(list)
    for item in parsed.values():
        by_name[item["name"]].append(item)
    hints = Counter(s["name_hint"] for s in sources.values())
    eligible = {p: item for p, item in parsed.items() if len(by_name[item["name"]]) == 1 and hints[item["name"]] == 1}
    complete = len(acquired) == len(sources) and len(parsed) == len(sources) and not diagnostics
    # Full-catalog closure is available only after every source has been acquired.
    if complete:
        activated, extra_diagnostics = activate_extras({"items": parsed, "diagnostics": []}, context)
        complete = not extra_diagnostics
        diagnostics.extend(extra_diagnostics)
    else:
        activated = deepcopy(parsed)
        for purl, item in activated.items():
            item["known"] = set(context.extras_by_purl.get(purl, []))
            if purl in context.root_purls:
                item["known"].update(context.active_extras)
        changed = True
        while changed:
            changed = False
            for item in activated.values():
                for _, req in item["requirements"]:
                    matches = [x for x in activated.values() if x["name"] == canonicalize_name(req.name)
                               and not req.url and req.specifier.contains(x["version"], prereleases=True)]
                    if marker(req, context, item["known"]) is not True or len(matches) != 1:
                        continue
                    before = set(matches[0]["known"])
                    matches[0]["known"].update(canonicalize_name(x) for x in req.extras)
                    changed |= before != matches[0]["known"]
    for purl, item in eligible.items():
        item["known"] = activated[purl].get("extras", activated[purl].get("known", set()))
        item["possible"] = activated[purl].get("possible_extras", activated[purl].get("possible", set())) if complete else None
        if complete and not set(item["known"]) <= set(item["possible"]):
            raise ValueError("Possible extras must include known extras")
    original_ids = identities(document)
    refs = {p: r for r, p in original_ids.items()}
    observed_names = Counter(canonicalize_name(row.get("name", "")) for row in native.packages().values())
    proposals, conflicts, candidates = [], [], []
    result = deepcopy(document)
    derived = NativeDocument(result)
    # Add nodes only from acquired, target-bound metadata; no registry/version guessing.
    for purl, item in sorted(eligible.items()):
        if purl in refs:
            continue
        if observed_names[item["name"]]:
            candidates.append({"purl": purl, "status": "UNKNOWN", "reason": "OBSERVED_IDENTITY_CONFLICT"})
            continue
        ref = ("SPDXRef-budget-" if native.format == "spdx" else "budget-") + sha([purl, item["source_id"]])[:24]
        component = {native.id_field: ref, "name": item["name"]}
        if native.format == "spdx":
            component.update(versionInfo=item["version"], downloadLocation="NOASSERTION", filesAnalyzed=False,
                externalRefs=[{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}])
        else:
            component.update(type="library", version=item["version"], purl=purl)
        proposal = RepairProposal(operation="add_component", subject=ref, value=component, evidence_ids=[item["source_id"]])
        derived.apply(proposal)
        refs[purl] = ref
        proposals.append(proposal.model_dump())
    frontier = Counter()
    for purl, parent in sorted(eligible.items()):
        if purl not in refs:
            continue
        for text, req in parent["requirements"]:
            name = canonicalize_name(req.name)
            active = marker(req, context, parent["known"])
            if req.url or active is not True:
                if active is not False:
                    candidates.append({"parent": purl, "requirement": text, "status": "UNKNOWN", "reason": "CONTEXT_OR_URL_UNCERTAIN"})
                continue
            matches = [item for item in eligible.values() if item["name"] == name and req.specifier.contains(item["version"], prereleases=True)]
            if len(matches) != 1 or matches[0]["purl"] not in refs:
                frontier[name] += 1
                candidates.append({"parent": purl, "requirement": text, "status": "UNKNOWN", "reason": "ENDPOINT_EVIDENCE_UNAVAILABLE_OR_AMBIGUOUS"})
                continue
            child = matches[0]
            source, target = refs[purl], refs[child["purl"]]
            if (source, target) in derived.edges():
                continue
            proposal = {"operation": "add_dependency", "subject": source, "field": None, "before": None,
                        "value": target, "evidence_ids": [parent["source_id"], child["source_id"]]}
            if native.declaration(source) is not None:
                conflicts.append({"proposal": proposal, "status": "CONFLICT", "reason": "EXISTING_DECLARATION_GATE"})
                continue
            derived.apply(RepairProposal(**proposal))
            proposals.append(proposal)
    # Reconcile original edges. Missing/extra-dependent metadata never becomes a negative.
    assessments, retract = [], set()
    for source, target in sorted(native.edges()):
        parent, child = eligible.get(original_ids.get(source)), eligible.get(original_ids.get(target))
        row = {"source_ref": source, "target_ref": target, "status": "UNKNOWN", "reason": "ENDPOINT_EVIDENCE_UNAVAILABLE_OR_AMBIGUOUS"}
        if parent and child:
            matching = [(text, req) for text, req in parent["requirements"] if canonicalize_name(req.name) == child["name"]]
            values = []
            for text, req in matching:
                possible = marker(req, context, parent["possible"]) if complete else (
                    None if req.marker and "extra" in str(req.marker) else marker(req, context, parent["known"]))
                values.append({"requirement": text, "possibly_active": possible})
            row.update(declarations=values, evidence_ids=[parent["source_id"], child["source_id"]])
            if matching and all(v["possibly_active"] is False for v in values):
                row.update(status="CONTRADICTED", reason="ALL_MATCHING_DECLARATIONS_INACTIVE")
                retract.add((source, target))
            elif any(not req.url and marker(req, context, parent["known"]) is True
                     and req.specifier.contains(child["version"], prereleases=True) for _, req in matching):
                row.update(status="SUPPORTED", reason="ACTIVE_VERSION_COMPATIBLE_DECLARATION")
            else:
                row["reason"] = "PARTIAL_EXTRAS_OR_DECLARATION_UNCERTAINTY"
        assessments.append(row)
    if native.format == "cyclonedx":
        for row in derived.data.get("dependencies", []):
            row["dependsOn"] = [t for t in row.get("dependsOn", []) if (row["ref"], t) not in retract]
        if proposals or retract:
            derived.data["version"] = derived.data.get("version", 1) + 1
    else:
        derived.data["relationships"] = [row for row in derived.data.get("relationships", []) if
            (row.get("relationshipType") not in {"DEPENDS_ON", "DEPENDENCY_OF"} or
             ((row.get("spdxElementId"), row.get("relatedSpdxElement")) if row.get("relationshipType") == "DEPENDS_ON"
              else (row.get("relatedSpdxElement"), row.get("spdxElementId"))) not in retract)]
    acquired_names = {item["name"] for item in eligible.values()}
    for row in native.packages().values():
        name = canonicalize_name(row.get("name", ""))
        if name not in acquired_names:
            frontier[name] += 1
    return {"policy": POLICY, "document": derived.data, "proposals": proposals, "conflicts": conflicts,
            "candidates": candidates, "assessments": assessments, "retracted_edges": sorted(map(list, retract)),
            "assessment_counts": dict(Counter(r["status"] for r in assessments)), "diagnostics": diagnostics,
            "frontier_names": dict(frontier), "complete_acquired_catalog": complete,
            "candidate_universe": "PARTIAL_CANDIDATE_UNIVERSE", "confidence": None,
            "context_status": "CONTEXT_BOUND_DECLARATIONS; partial extras remain uncertain",
            "input_sha256": sha(document), "output_sha256": sha(derived.data),
            "path_absence_status": "UNKNOWN", "verification_scope": "Acquired target metadata declarations only; not installed artifact or exploitability attestation"}
