"""Explicit comparison policies; observed agreement never grants verification.

``naive_union`` groups exact PURLs across occurrences, exposing the usual union
assumption. ``fixed_priority`` and ``majority`` group by ecosystem/name/locator
(or name when location is missing), then select observed metadata. These are
deliberately occurrence-naive comparators, not evidence verification methods.
``single:<source_id>`` preserves that document's native occurrences. The
``lockfile_only`` control predicts exclusively from acquired lockfile/native
resolution facts, with the same scope/admissibility rules as the main engine.
"""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy

from sbom_recovery.core.formats import sha

from .engine import reconcile


METHODS = ("naive_union", "fixed_priority", "majority", "lockfile_only")


def _id(prefix, value):
    return prefix + sha(value)[:24]


def _family(observation):
    identity = observation["identity"]
    return (identity.get("ecosystem"), identity.get("namespace"), identity.get("name"), observation.get("locator"))


def baseline(state, method, acquired=()):
    """Return an engine-compatible result, preserving raw inputs and assumptions."""
    if method == "lockfile_only":
        empty = {**deepcopy(state), "observations": [], "source_edges": []}
        result = reconcile(empty, [s for s in acquired if s.get("kind") in {"lockfile", "native_resolution"}])
        result["method"] = method
        result["baseline_choices"] = [{"policy": "SCOPED_LOCKFILE_AND_NATIVE_RESOLUTION_ONLY",
                                       "scanner_assertions_used": False}]
        return result
    if method.startswith("single:"):
        source_id = method.split(":", 1)[1]
        documents = [d for d in state["source_documents"] if d["source_id"] == source_id]
        if len(documents) != 1:
            raise ValueError("Unknown single-scanner source ID")
        selected = {o["observation_id"] for o in state["observations"] if source_id in o["source_ids"]}
        filtered = {**deepcopy(state), "source_documents": deepcopy(documents),
                    "observations": [deepcopy(o) for o in state["observations"] if o["observation_id"] in selected],
                    "source_edges": [deepcopy(e) for e in state["source_edges"] if e["source"] in selected and e["target"] in selected]}
        result = reconcile(filtered, [], metadata=False, graph=False)
        result["method"] = method
        result["baseline_choices"] = [{"policy": "SINGLE_NATIVE_DOCUMENT", "source_id": source_id}]
        return result
    if method not in METHODS:
        raise ValueError("Unknown investigation baseline")
    result = reconcile(state, [], metadata=False, graph=False)
    order = {d["source_id"]: index for index, d in enumerate(state["source_documents"])}
    observations = sorted(state["observations"], key=lambda o: (
        min(order[s] for s in o["source_ids"]), o["observation_id"]))
    groups = defaultdict(list)
    for observation in observations:
        identity = observation["identity"]
        if method == "naive_union":
            key = ("purl", identity["purl"]) if identity.get("purl") else ("observation", observation["observation_id"])
        else:
            key = ("family", *_family(observation))
        groups[key].append(observation)
    components, choices, mapping, alignment, claims, decisions = [], [], {}, [], [], []
    for key, candidates in groups.items():
        variants = defaultdict(list)
        for candidate in candidates:
            variants[sha(candidate["identity"])].append(candidate)
        votes = {identity: len({o["document_sha256"] for o in records}) for identity, records in variants.items()}
        if method == "majority":
            winning_score = max(votes.values())
            # Source order resolves ties, and this assumption is recorded below.
            winner = next(o for o in candidates if votes[sha(o["identity"])] == winning_score)
        else:
            winner = candidates[0]
        cid = _id("baseline-", [method, key])
        identity = winner["identity"]
        locator_values = {o.get("locator") for o in candidates}
        component = {"id": cid, **deepcopy(identity), "locator": next(iter(locator_values)) if len(locator_values) == 1 else None,
                     "status": "UNKNOWN", "evidence_ids": [], "observation_ids": sorted(o["observation_id"] for o in candidates),
                     "field_candidates": {}, "root": any(o["root"] for o in candidates), "binding": "BASELINE_ASSUMPTION"}
        components.append(component)
        choices.append({"component_id": cid, "policy": method, "chosen_observation_id": winner["observation_id"],
                        "candidate_observation_ids": component["observation_ids"], "votes_by_identity_sha256": votes,
                        "tie_break": "SOURCE_ORDER", "verification": "UNVERIFIED_OBSERVATION_SELECTION",
                        "occurrence_preservation": "NOT_GUARANTEED"})
        for observation in candidates:
            oid = observation["observation_id"]
            mapping[oid] = cid
            alignment.append({"observation_id": oid, "component_id": cid, "status": "BASELINE_ASSUMPTION",
                              "evidence_ids": [], "reason": method + ": selected observed identity without verification"})
            for field in ("name", "version", "purl", "origin", "digest"):
                value = observation["identity"].get(field)
                if value is not None:
                    claims.append({"claim_id": _id("baseline-claim-", [oid, field]), "subject": cid,
                                   "observation_id": oid, "predicate": field, "value": value,
                                   "scope": deepcopy(observation["scope"]), "status": "UNKNOWN",
                                   "support_evidence_ids": [], "refutation_evidence_ids": [],
                                   "reason": "Observed assertion; baseline selection does not verify it"})
                chosen = identity.get(field)
                if chosen is not None and value != chosen:
                    decisions.append({"decision_id": _id("baseline-decision-", [method, oid, field]),
                                      "operation": "SET_FIELD", "disposition": "APPLY", "subject": cid,
                                      "observation_id": oid, "locator": observation.get("locator"), "field": field,
                                      "before": value, "value": chosen, "evidence_ids": [],
                                      "verification": "UNVERIFIED_BASELINE_CHOICE"})
    edge_rows = {}
    for source in state["source_edges"]:
        a, b = mapping[source["source"]], mapping[source["target"]]
        key = (a, b, source["relationship_type"], source["scope"])
        if key not in edge_rows:
            edge_rows[key] = {"id": _id("baseline-edge-", [method, key]), "source": a, "target": b,
                              "relationship_type": key[2], "scope": key[3], "status": "UNKNOWN", "evidence_ids": [],
                              "support_evidence_ids": [], "refutation_evidence_ids": [], "observation_ids": [],
                              "native_relationships": [], "disposition": "PRESERVE_OBSERVATION",
                              "source_scope_compatible": False}
        row = edge_rows[key]
        row["observation_ids"].append(source["observation_id"])
        row["native_relationships"].append(source["native_relationship"])
        expected = {"target_id": state["target"]["target_id"], "revision_ref": state["target"].get("revision_ref"),
                    "context_id": state["target"]["context"]["context_id"], "view": state["target"]["view"]}
        row["source_scope_compatible"] |= all(v is not None and source["source_scope"].get(k) == v for k, v in expected.items())
    for edge in edge_rows.values():
        claims.append({"claim_id": edge["id"], "subject": edge["source"], "predicate": edge["relationship_type"],
                       "value": edge["target"], "scope": {"dependency_scope": edge["scope"]}, "status": "UNKNOWN",
                       "support_evidence_ids": [], "refutation_evidence_ids": [],
                       "reason": "Observed relationship after unverified baseline identity selection"})
    result.update(method=method, components=sorted(components, key=lambda c: c["id"]),
                  edges=sorted(edge_rows.values(), key=lambda e: e["id"]), alignment=alignment,
                  claims=claims, decisions=decisions, baseline_choices=choices,
                  roots=sorted(c["id"] for c in components if c["root"]),
                  configuration={"metadata": False, "graph": False, "baseline": method},
                  trust_model="Observed baseline selections; producer votes and priorities are not verification")
    return result
