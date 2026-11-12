"""Evidence-grounded, occurrence-preserving reconciliation of native SBOMs.

The controller supplies digest-checked evidence. This module independently checks
its target scope and computes bindings; neither producer agreement nor a matching
PURL proves that two physical occurrences are the same occurrence.
"""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import json

from packageurl import PackageURL

from sbom_recovery.core.formats import NativeDocument, canonical_purl, package_purl, sha, validate_native
from sbom_recovery.reconciliation.merge_contracts_v3 import ReconciliationRequestV3
from .evidence import read_frozen_blob


def _id(prefix, value):
    return prefix + sha(value)[:24]


def _scope(target):
    return {"target_id": target["target_id"], "revision_ref": target.get("revision_ref"),
            "context_id": target["context"]["context_id"], "view": target["view"]}


def _compatible(scope, target):
    wanted = _scope(target)
    return isinstance(scope, dict) and all(wanted[k] is not None and scope.get(k) == wanted[k] for k in wanted)


def _read(base_dir, blob):
    return json.loads(read_frozen_blob(base_dir, blob.path, blob.sha256, 32 * 1024 * 1024))


def _purl_name(parsed):
    if parsed.type == "npm" and parsed.namespace:
        return (parsed.namespace if parsed.namespace.startswith("@") else "@" + parsed.namespace) + "/" + parsed.name
    return parsed.name


def _identity(item, fmt):
    purl = package_purl(item, fmt)
    parsed = PackageURL.from_string(purl) if purl else None
    return {"ecosystem": parsed.type if parsed else None, "namespace": parsed.namespace if parsed else None,
            "name": item.get("name", _purl_name(parsed) if parsed else None),
            "version": item.get("version" if fmt == "cyclonedx" else "versionInfo", parsed.version if parsed else None),
            "purl": purl, "origin": None, "digest": None}


def _locator(item, fmt):
    candidates = []
    if fmt == "cyclonedx":
        candidates.extend(p.get("value") for p in item.get("properties", []) if p.get("name") in {
            "sbom-recovery:locator", "syft:location:0:path"})
        candidates.extend(o.get("location") for o in item.get("evidence", {}).get("occurrences", []))
    else:
        candidates.extend(a["comment"].split("=", 1)[1] for a in item.get("annotations", [])
                          if a.get("comment", "").startswith("sbom-recovery:locator="))
    candidates = sorted(set(v for v in candidates if isinstance(v, str)))
    return (candidates[0] if len(candidates) == 1 else None), candidates


def _source_edges(native):
    if native.format == "cyclonedx":
        for row in native.data.get("dependencies", []):
            for endpoint in row.get("dependsOn", []):
                yield {"source": row["ref"], "target": endpoint, "relationship_type": "direct_dependency",
                       "scope": "unknown", "native_relationship": "dependsOn"}
        return
    dependency_scopes = {"BUILD_DEPENDENCY_OF": "build", "DEV_DEPENDENCY_OF": "development",
                         "TEST_DEPENDENCY_OF": "test", "RUNTIME_DEPENDENCY_OF": "runtime",
                         "OPTIONAL_DEPENDENCY_OF": "optional", "PROVIDED_DEPENDENCY_OF": "provided"}
    for row in native.data.get("relationships", []):
        a, b, relation = row.get("spdxElementId"), row.get("relatedSpdxElement"), row.get("relationshipType")
        if relation in {"DESCRIBES", "DESCRIBED_BY"}:
            continue
        if relation == "DEPENDS_ON":
            kind, scope = "direct_dependency", "unknown"
        elif relation == "DEPENDENCY_OF" or relation in dependency_scopes:
            a, b = b, a
            kind, scope = "direct_dependency", dependency_scopes.get(relation, "unknown")
        elif relation in {"CONTAINS", "CONTAINED_BY"}:
            if relation == "CONTAINED_BY":
                a, b = b, a
            kind, scope = "contains", "unknown"
        elif relation == "BUILD_TOOL_OF":
            kind, scope = "build_input_of", "build"
        else:
            kind, scope = "unsupported:" + str(relation), "unknown"
        yield {"source": a, "target": b, "relationship_type": kind,
               "scope": scope, "native_relationship": relation}


def ingest(request, base_dir):
    """Read only declared blobs, check bytes/format/refs, retain all native fields."""
    request = request if isinstance(request, ReconciliationRequestV3) else ReconciliationRequestV3.model_validate(request)
    target, observations, documents, edges, issues = request.target.model_dump(), {}, [], [], []
    seen_docs = set()
    for source in request.documents:
        document = _read(base_dir, source.document)
        native = NativeDocument(document)
        expected = "CycloneDX" if native.format == "cyclonedx" else "SPDX"
        if expected != source.format:
            raise ValueError("SBOM format differs from declared format")
        validation = validate_native(document)
        if not validation["valid"]:
            raise ValueError("Invalid native SBOM: " + json.dumps(validation["errors"])[:1000])
        source_scope = {"target_id": source.target_id, "revision_ref": source.revision_ref,
                        "context_id": source.context_id, "view": source.view}
        digest = source.document.sha256
        documents.append({"source_id": source.source_id, "sha256": digest, "format": source.format,
                          "scope": source_scope, "producer": source.producer.model_dump(), "document": document})
        roots = set()
        if native.format == "cyclonedx":
            root = document.get("metadata", {}).get("component", {}).get("bom-ref")
            if root:
                roots.add(root)
        else:
            described = {r["relatedSpdxElement"] for r in document.get("relationships", [])
                         if r.get("spdxElementId") == document.get("SPDXID") and r.get("relationshipType") == "DESCRIBES"}
            if len(described) == 1:
                roots.update(described)
            elif described:
                issues.append({"code": "AMBIGUOUS_DOCUMENT_ROOT", "source_id": source.source_id,
                               "reason": "Describing multiple packages does not identify an application dependency root"})
        for ref, item in native.packages().items():
            key = digest + ":" + ref
            if key in observations:
                observations[key]["source_ids"].append(source.source_id)
                if observations[key]["scope"] != source_scope:
                    observations[key]["scope"] = {}  # conflicting grouping labels do not grant a binding
                continue
            locator, locators = _locator(item, native.format)
            observations[key] = {"observation_id": key, "document_sha256": digest, "native_ref": ref,
                                 "source_ids": [source.source_id], "scope": source_scope,
                                 "identity": _identity(item, native.format), "locator": locator,
                                 "locator_candidates": locators, "root": ref in roots,
                                 "native_format": native.format, "native_record": deepcopy(item)}
            identity = observations[key]["identity"]
            if identity.get("purl"):
                parsed = PackageURL.from_string(identity["purl"])
                if parsed.version is not None and identity.get("version") not in {None, parsed.version}:
                    issues.append({"code": "OBSERVED_PURL_VERSION_CONFLICT", "observation_id": key,
                                   "version": identity["version"], "purl_version": parsed.version})
        if digest in seen_docs:
            continue  # identical bytes are one observation, not an independent vote
        seen_docs.add(digest)
        for index, edge in enumerate(_source_edges(native)):
            a, b = digest + ":" + str(edge["source"]), digest + ":" + str(edge["target"])
            if a not in observations or b not in observations:
                issues.append({"code": "UNSUPPORTED_EDGE_ENDPOINT", "source_id": source.source_id,
                               "native_edge": edge})
                continue
            edges.append({**edge, "source": a, "target": b, "observation_id": digest + ":edge:" + str(index),
                          "source_ids": [source.source_id], "source_scope": source_scope})
    # Identical bytes with inconsistent caller scope labels are not a known-scope
    # graph merely because the first descriptor happened to be complete.
    for edge in edges:
        a_scope, b_scope = observations[edge["source"]]["scope"], observations[edge["target"]]["scope"]
        if a_scope != b_scope or a_scope != edge["source_scope"]:
            edge["source_scope"] = {}
    return {"schema_version": "reconciliation-state-v3", "target": target,
            "observations": list(observations.values()), "source_documents": documents,
            "source_edges": edges, "issues": issues}


def _fact_identity(fact):
    purl = fact.get("purl")
    if purl:
        try:
            purl = canonical_purl(purl)
            p = PackageURL.from_string(purl)
        except (ValueError, TypeError):
            return None
        if any(fact.get(k) is not None and fact[k] != value for k, value in (
            ("ecosystem", p.type), ("version", p.version), ("namespace", p.namespace))):
            return None
        if fact.get("name") not in {None, p.name, _purl_name(p)}:
            return None
    else:
        p = None
    return {"ecosystem": fact.get("ecosystem", p.type if p else None),
            "namespace": fact.get("namespace", p.namespace if p else None),
            "name": _purl_name(p) if p else fact.get("name"), "version": fact.get("version", p.version if p else None),
            "purl": purl, "origin": fact.get("origin"), "digest": fact.get("digest")}


def _identity_key(identity):
    return tuple(identity.get(k) for k in ("ecosystem", "namespace", "name", "version", "purl", "origin", "digest"))


def _merge_partial_identities(records):
    """Missing evidence is neutral. Conflict applies to the disputed field only."""
    fields = ("ecosystem", "namespace", "name", "version", "purl", "origin", "digest")
    values = {field: sorted({r["identity"][field] for r in records if r["identity"].get(field) is not None})
              for field in fields}
    merged = {field: known[0] if len(known) == 1 else None for field, known in values.items()}
    conflicts = {field: known for field, known in values.items() if len(known) > 1}
    core_conflict = bool(set(conflicts) & {"ecosystem", "namespace", "name", "version", "purl"})
    statuses = {field: "CONFLICT" if field in conflicts else "SUPPORTED" if known else "UNKNOWN"
                for field, known in values.items()}
    return merged, conflicts, core_conflict, statuses


def _same_identity(left, right):
    if left.get("purl") and right.get("purl"):
        return (left["purl"] == right["purl"] and left.get("version") == right.get("version")
                and left.get("name") == right.get("name"))
    return all(left.get(k) is not None and left.get(k) == right.get(k) for k in ("ecosystem", "name", "version"))


def _status(positive, negative):
    return {(True, False): "SUPPORTED", (False, True): "REFUTED", (True, True): "CONFLICT",
            (False, False): "UNKNOWN"}[bool(positive), bool(negative)]


def reconcile(state, acquired, metadata=True, graph=True):
    """Recompute from immutable observations; every evidence claim is scoped anew."""
    target = state["target"]
    issues = deepcopy(state.get("issues", []))
    admitted = []
    by_locator, by_purl = defaultdict(list), defaultdict(list)
    facts_by_source = {}
    for source in acquired:
        facts = source.get("facts", {})
        if source.get("status") != "OK" or source.get("candidate_only") or source.get("kind") == "registry_metadata":
            continue
        if not _compatible(facts.get("scope"), target):
            issues.append({"code": "EVIDENCE_SCOPE_UNBOUND", "source_id": source.get("source_id")})
            continue
        allowed_views = {"manifest": {"DECLARED"}, "lockfile": {"RESOLVED"}, "native_resolution": {"RESOLVED"},
                         "build_record": {"RESOLVED", "ARTIFACT"}, "bundler_metafile": {"RESOLVED", "ARTIFACT"}}
        if target["view"] not in allowed_views.get(source.get("kind"), set()):
            issues.append({"code": "EVIDENCE_KIND_NOT_ADMISSIBLE", "source_id": source.get("source_id")})
            continue
        source_id = source["source_id"]
        # A complete source is still a collector assertion, not a build attestation.
        if source_id in facts_by_source:
            if facts_by_source[source_id] != facts:
                raise ValueError("Acquired source ID changed facts")
            continue
        facts_by_source[source_id] = facts
        admitted.append({k: deepcopy(source[k]) for k in ("source_id", "kind", "sha256", "facts") if k in source})
        seen_occurrences = set()
        for fact in facts.get("components", []):
            identity = _fact_identity(fact)
            occurrence = fact.get("occurrence_id")
            if not identity or not isinstance(occurrence, str) or occurrence in seen_occurrences:
                issues.append({"code": "INVALID_EVIDENCE_COMPONENT", "source_id": source_id})
                continue
            seen_occurrences.add(occurrence)
            record = {"source_id": source_id, "occurrence_id": occurrence, "identity": identity,
                      "locator": fact.get("locator")}
            if isinstance(record["locator"], str):
                by_locator[record["locator"]].append(record)
            if identity.get("purl"):
                by_purl[identity["purl"]].append(record)

    components, alignment, claims, conflicts, decisions = {}, [], [], [], []
    obs_map, occurrence_map = {}, defaultdict(set)
    observations_by_locator = defaultdict(list)
    for observation in state["observations"]:
        if observation.get("locator") is not None and _compatible(observation.get("scope"), target):
            observations_by_locator[observation["locator"]].append(observation)

    def make_component(component_id, identity, locator, status="UNKNOWN", evidence_ids=()):
        if component_id not in components:
            components[component_id] = {"id": component_id, **deepcopy(identity), "locator": locator,
                                        "status": status, "evidence_ids": sorted(set(evidence_ids)),
                                        "observation_ids": [], "field_candidates": {}, "root": False}
        return components[component_id]

    for observation in state["observations"]:
        oid, identity, locator = observation["observation_id"], observation["identity"], observation.get("locator")
        scoped = _compatible(observation.get("scope"), target)
        records = by_locator.get(locator, []) if scoped and locator is not None else []
        identities = {_identity_key(r["identity"]): r["identity"] for r in records}
        candidates = list(identities.values())
        merged, field_conflicts, core_conflict, field_statuses = _merge_partial_identities(records)
        support = sorted({r["source_id"] for r in records})
        if records and not core_conflict and (metadata or _same_identity(identity, merged)):
            selected = merged if metadata else identity
            cid = _id("occ-", [_scope(target), locator])
            component = make_component(cid, selected, locator, "SUPPORTED", support)
            component["field_statuses"] = field_statuses
            component["field_candidates"] = deepcopy(field_conflicts)
            resolution = "SAME"
            for field, values in field_conflicts.items():
                conflicts.append({"subject": cid, "kind": "FIELD_EVIDENCE_CONFLICT", "field": field,
                                  "evidence_ids": support, "candidates": values})
            for record in records:
                occurrence_map[(record["source_id"], record["occurrence_id"])].add(cid)

            if metadata:
                for field in ("name", "version", "purl", "origin", "digest"):
                    if selected.get(field) is not None and selected.get(field) != identity.get(field):
                        decisions.append({"decision_id": _id("decision-", [oid, field]), "disposition": "APPLY",
                                          "operation": "SET_FIELD", "subject": cid, "locator": locator,
                                          "field": field, "before": identity.get(field), "value": selected[field],
                                          "observation_id": oid,
                                          "evidence_ids": sorted({r["source_id"] for r in records
                                                                  if r["identity"].get(field) == selected[field]}),
                                          "claim_ids": [_id("selected-field-", [cid, field])],
                                          "original_claim_id": _id("claim-", [oid, field])})
        elif core_conflict and metadata:
            cid = _id("conflict-", [_scope(target), locator])
            component = make_component(cid, merged, locator, "CONFLICT", support)
            component["field_statuses"] = field_statuses
            component["field_candidates"] = {k: sorted({v[k] for v in candidates if v.get(k) is not None}) for k in identity}
            resolution = "CONFLICT"
            conflicts.append({"subject": cid, "kind": "IDENTITY_EVIDENCE_CONFLICT", "evidence_ids": support,
                              "candidates": candidates})
        else:
            cid = _id("obs-", oid)
            exact = [r for r in by_purl.get(identity.get("purl"), []) if _same_identity(identity, r["identity"])] if scoped else []
            exact_ids = sorted({r["source_id"] for r in exact})
            component = make_component(cid, identity, locator, "SUPPORTED" if exact_ids else "UNKNOWN", exact_ids)
            component["binding"] = "IDENTITY_ONLY" if exact_ids else "UNRESOLVED"
            resolution = "UNRESOLVED"
        component["observation_ids"].append(oid)
        component["root"] = component["root"] or observation["root"]
        obs_map[oid] = cid
        alignment.append({"observation_id": oid, "component_id": cid, "status": resolution,
                          "evidence_ids": support if resolution != "UNRESOLVED" else [],
                          "reason": "Target-scoped locator binding" if resolution == "SAME" else "Occurrence unresolved or conflicting"})
        for field in ("name", "version", "purl", "origin", "digest"):
            value = identity.get(field)
            if value is None:
                continue
            positives = sorted({r["source_id"] for r in records if r["identity"].get(field) == value})
            negatives = sorted({r["source_id"] for r in records if r["identity"].get(field) not in (None, value)})
            claims.append({"claim_id": _id("claim-", [oid, field]), "subject": cid, "observation_id": oid,
                           "predicate": field, "value": value, "scope": deepcopy(observation["scope"]),
                           "status": _status(positives, negatives), "support_evidence_ids": positives,
                           "refutation_evidence_ids": negatives,
                           "reason": "Field comparison against target-scoped metadata at the same locator"})

    # Evidence-only occurrences can be added only by the metadata arm and with an
    # unambiguous target locator. Registry identity matches never enter here.
    if metadata:
        for locator, records in sorted(by_locator.items()):
            if locator in observations_by_locator:
                continue
            merged, field_conflicts, core_conflict, field_statuses = _merge_partial_identities(records)
            if core_conflict:
                conflicts.append({"subject": locator, "kind": "UNOBSERVED_IDENTITY_CONFLICT",
                                  "evidence_ids": sorted({r["source_id"] for r in records})})
                continue
            cid = _id("occ-", [_scope(target), locator])
            component = make_component(cid, merged, locator, "SUPPORTED",
                                       [r["source_id"] for r in records])
            component["field_statuses"] = field_statuses
            component["field_candidates"] = deepcopy(field_conflicts)
            for field, values in field_conflicts.items():
                conflicts.append({"subject": cid, "kind": "FIELD_EVIDENCE_CONFLICT", "field": field,
                                  "evidence_ids": component["evidence_ids"], "candidates": values})
            component["root"] = locator == ""
            decisions.append({"decision_id": _id("add-", cid), "disposition": "APPLY", "operation": "ADD_COMPONENT",
                              "subject": cid, "locator": locator, "evidence_ids": component["evidence_ids"],
                              "claim_ids": [_id("identity-", cid)]})
            for record in records:
                occurrence_map[(record["source_id"], record["occurrence_id"])].add(cid)

    # Native selected roots are independently collected facts. Preserve them in
    # the lockfile-only arm as well as when no source SBOM observed the root.
    for source_id, facts in facts_by_source.items():
        for root in facts.get("roots", []):
            bound = occurrence_map.get((source_id, root), set())
            if len(bound) == 1:
                components[next(iter(bound))]["root"] = True

    edge_claims = {}

    def edge_claim(a, b, kind, scope):
        key = (a, b, kind, scope or "unknown")
        if key not in edge_claims:
            edge_claims[key] = {"id": _id("edge-", key), "source": a, "target": b,
                                "relationship_type": kind, "scope": key[3], "status": "UNKNOWN",
                                "evidence_ids": [], "support_evidence_ids": [], "refutation_evidence_ids": [],
                                "observation_ids": [], "native_relationships": []}
        return edge_claims[key]

    for edge in state["source_edges"]:
        row = edge_claim(obs_map[edge["source"]], obs_map[edge["target"]], edge["relationship_type"], edge["scope"])
        row["observation_ids"].append(edge["observation_id"])
        row["native_relationships"].append(edge["native_relationship"])
        row["source_scope_compatible"] = row.get("source_scope_compatible", False) or _compatible(edge["source_scope"], target)

    if graph:
        mapped_edges_by_source = {}
        for source_id, facts in facts_by_source.items():
            mapped_edges = set()
            for edge in facts.get("edges", []):
                a = occurrence_map.get((source_id, edge.get("source")), set())
                b = occurrence_map.get((source_id, edge.get("target")), set())
                if len(a) != 1 or len(b) != 1:
                    issues.append({"code": "EVIDENCE_EDGE_ENDPOINT_UNRESOLVED", "source_id": source_id,
                                   "edge": deepcopy(edge)})
                    continue
                kind = edge.get("relationship_type")
                if kind not in {"direct_dependency", "contains", "build_input_of"}:
                    issues.append({"code": "UNSUPPORTED_EVIDENCE_RELATIONSHIP", "source_id": source_id})
                    continue
                if ((kind == "contains" and target["view"] != "ARTIFACT")
                        or (kind == "direct_dependency" and target["view"] == "ARTIFACT")
                        or (kind == "build_input_of" and target["view"] != "RESOLVED")):
                    issues.append({"code": "EVIDENCE_RELATIONSHIP_VIEW_MISMATCH", "source_id": source_id})
                    continue
                a, b = next(iter(a)), next(iter(b))
                scope = edge.get("scope") or "unknown"
                row = edge_claim(a, b, kind, scope)
                row["support_evidence_ids"].append(source_id)
                mapped_edges.add((a, b, kind, scope))
            mapped_edges_by_source[source_id] = mapped_edges
        # Evaluate closure after collecting *all* positive candidates. Otherwise a
        # newly discovered edge could evade an earlier source's negative evidence.
        for source_id, facts in facts_by_source.items():
            mapped_edges = mapped_edges_by_source[source_id]
            for coverage in facts.get("coverage", []):
                if coverage.get("domain") != "direct_dependency" or coverage.get("complete") is not True:
                    continue
                subjects = occurrence_map.get((source_id, coverage.get("subject")), set())
                if len(subjects) != 1:
                    continue
                subject = next(iter(subjects))
                coverage_scope = coverage.get("scope") or "unknown"
                for key, row in edge_claims.items():
                    if (row["source"] == subject and row["relationship_type"] == "direct_dependency"
                            and row["scope"] == coverage_scope and key not in mapped_edges):
                        # Both endpoints must be bound in this inventory. A missing
                        # target is never sufficient negative evidence.
                        bound = set().union(*(v for (s, _), v in occurrence_map.items() if s == source_id))
                        if row["target"] in bound:
                            row["refutation_evidence_ids"].append(source_id)

    for row in edge_claims.values():
        row["support_evidence_ids"] = sorted(set(row["support_evidence_ids"]))
        row["refutation_evidence_ids"] = sorted(set(row["refutation_evidence_ids"]))
        row["evidence_ids"] = sorted(set(row["support_evidence_ids"] + row["refutation_evidence_ids"]))
        row["status"] = _status(row["support_evidence_ids"], row["refutation_evidence_ids"])
        row["disposition"] = ("APPLY" if row["status"] == "SUPPORTED" else "RETRACT" if row["status"] == "REFUTED"
                              else "PRESERVE_OBSERVATION" if row["observation_ids"] else "DEFER")
        if row["status"] == "CONFLICT":
            row["disposition"] = "DEFER"
            conflicts.append({"subject": row["id"], "kind": "EDGE_EVIDENCE_CONFLICT", "evidence_ids": row["evidence_ids"]})
        claims.append({"claim_id": row["id"], "subject": row["source"], "predicate": row["relationship_type"],
                       "value": row["target"], "scope": {**_scope(target), "dependency_scope": row["scope"]},
                       "status": row["status"], "support_evidence_ids": row["support_evidence_ids"],
                       "refutation_evidence_ids": row["refutation_evidence_ids"],
                       "reason": "Scoped endpoint binding and native relationship/closure evidence"})
    for component in components.values():
        component["observation_ids"].sort()
        if component["status"] == "SUPPORTED":
            records = by_locator.get(component.get("locator"), [])
            for field in ("ecosystem", "namespace", "name", "version", "purl", "origin", "digest"):
                value = component.get(field)
                if value is None:
                    continue
                support = sorted({r["source_id"] for r in records if r["identity"].get(field) == value})
                if not support:
                    # Identity-only binding has no occurrence locator. Its PURL
                    # claim is still grounded in selected metadata, never merged.
                    support = sorted({r["source_id"] for r in by_purl.get(component.get("purl"), [])
                                      if r["identity"].get(field) == value})
                if support:
                    claims.append({"claim_id": _id("selected-field-", [component["id"], field]),
                                   "subject": component["id"], "predicate": field, "value": value,
                                   "scope": _scope(target), "status": "SUPPORTED", "support_evidence_ids": support,
                                   "refutation_evidence_ids": [], "reason": "Field-specific selected metadata evidence"})
            claims.append({"claim_id": _id("identity-", component["id"]), "subject": component["id"],
                           "predicate": "identity", "value": {k: component.get(k) for k in (
                               "ecosystem", "namespace", "name", "version", "purl", "origin", "digest")},
                           "scope": _scope(target), "status": "SUPPORTED",
                           "support_evidence_ids": component["evidence_ids"], "refutation_evidence_ids": [],
                           "reason": "Identity supported by target-scoped metadata; occurrence binding reported separately"})
    return {"schema_version": "reconciliation-result-v3", "target": deepcopy(target),
            "configuration": {"metadata": metadata, "graph": graph},
            "components": sorted(components.values(), key=lambda c: c["id"]),
            "edges": sorted(edge_claims.values(), key=lambda e: e["id"]),
            "alignment": alignment, "claims": claims, "conflicts": conflicts, "issues": issues, "decisions": decisions,
            "raw_observations": deepcopy(state["observations"]), "source_documents": deepcopy(state["source_documents"]),
            "evidence": admitted, "roots": sorted(c["id"] for c in components.values() if c["root"]),
            "path_absence_status": "UNKNOWN", "exploitability": "NOT_ASSESSED",
            "trust_model": "Digest-frozen collector snapshots; target labels are not cryptographic build attestations"}


def export(result):
    """Return native projections plus lossless provenance sidecars.

    Observed unknown edges remain observed; conflicting/new unsupported edges are
    deferred. Missing outgoing records remain missing, never an invented [] claim.
    """
    components = [c for c in result["components"] if c["status"] != "REFUTED"]
    known = {c["id"] for c in components}
    active_edges = [e for e in result["edges"] if e["source"] in known and e["target"] in known
                    and (e["status"] == "SUPPORTED" or (e["status"] == "UNKNOWN" and e["observation_ids"]
                                                        and e.get("source_scope_compatible")))]
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}
    spdx = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Evidence-grounded reconciliation: " + result["target"]["target_id"],
            "documentNamespace": "https://sbom-recovery.invalid/reconciled/" + sha(result),
            "creationInfo": {"creators": ["Tool: sbom-recovery-v3"],
                             "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
            "packages": [], "relationships": []}
    refmap = {c["id"]: "SPDXRef-" + c["id"] for c in components}
    for component in components:
        cid = component["id"]
        name = component.get("name") or "unresolved-component"
        properties = [{"name": "sbom-recovery:status", "value": component["status"]},
                      {"name": "sbom-recovery:observation-ids", "value": json.dumps(component["observation_ids"])}]
        if component.get("locator") is not None:
            properties.append({"name": "sbom-recovery:locator", "value": component["locator"]})
        item = {"type": "application" if component.get("root") else "library", "bom-ref": cid,
                "name": name, "properties": properties}
        package = {"SPDXID": refmap[cid], "name": name, "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                   "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION"}
        if component.get("version") is not None:
            item["version"] = component["version"]
            package["versionInfo"] = component["version"]
        if component.get("purl"):
            item["purl"] = component["purl"]
            package["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                         "referenceLocator": component["purl"]}]
        cdx["components"].append(item)
        spdx["packages"].append(package)
        if component.get("root"):
            spdx["relationships"].append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                                           "relatedSpdxElement": refmap[cid]})
    # DESCRIBES identifies the document's subject, not a dependency relationship.
    # A rootless inventory may describe all its packages without inventing an
    # application root or connecting those packages in the dependency graph.
    if components and not any(c.get("root") for c in components):
        spdx["relationships"].extend({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                                      "relatedSpdxElement": refmap[c["id"]]} for c in components)
    deps = defaultdict(set)
    spdx_scopes = {"build": "BUILD_DEPENDENCY_OF", "development": "DEV_DEPENDENCY_OF", "test": "TEST_DEPENDENCY_OF",
                   "runtime": "RUNTIME_DEPENDENCY_OF", "optional": "OPTIONAL_DEPENDENCY_OF", "provided": "PROVIDED_DEPENDENCY_OF"}
    for edge in active_edges:
        a, b, kind = edge["source"], edge["target"], edge["relationship_type"]
        if kind == "direct_dependency":
            deps[a].add(b)
            relation = spdx_scopes.get(edge["scope"], "DEPENDS_ON")
            if relation != "DEPENDS_ON":
                a, b = b, a
        elif kind == "contains":
            relation = "CONTAINS"
        elif kind == "build_input_of":
            relation = "BUILD_TOOL_OF"
        elif kind.startswith("unsupported:"):
            relation = kind.split(":", 1)[1]
        else:
            continue
        spdx["relationships"].append({"spdxElementId": refmap[a], "relatedSpdxElement": refmap[b],
                                      "relationshipType": relation})
    if deps:
        cdx["dependencies"] = [{"ref": source, "dependsOn": sorted(targets)} for source, targets in sorted(deps.items())]
    validations = {"CycloneDX": validate_native(cdx), "SPDX": validate_native(spdx)}
    return {"unified.spdx.json": spdx, "unified.cdx.json": cdx,
            "evidence.json": {"schema_version": "reconciliation-evidence-ledger-v3", "target": result["target"],
                              "configuration": result["configuration"],
                              "baseline_choices": result.get("baseline_choices", []),
                              "evidence": result["evidence"], "claims": result["claims"], "alignment": result["alignment"],
                              "decisions": result["decisions"],
                              "raw_observations": result["raw_observations"], "source_documents": result["source_documents"],
                              "trust_model": result["trust_model"]},
            "conflict-report.json": {"conflicts": result["conflicts"], "issues": result["issues"]},
            "dependency-graph.json": {"components": result["components"], "edges": result["edges"],
                                      "roots": result["roots"], "path_absence_status": "UNKNOWN", "exploitability": "NOT_ASSESSED"},
            "validation-report.json": {"valid": all(v["valid"] for v in validations.values()), "formats": validations,
                                       "content_correctness": "NOT_PROVEN_BY_SCHEMA", "source_fields_preserved_in": "evidence.json"}}
