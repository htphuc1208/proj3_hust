"""Project-group split conformal sets; temporal exchangeability is explicitly unverified."""
from collections import defaultdict
import math
from pathlib import Path
from packaging.utils import canonicalize_name

from sbom_recovery.core.research_core import load
from sbom_recovery.core.formats import NativeDocument, package_purl, canonical_purl, sha
from sbom_recovery.evidence.storage import save


def fit_project_conformal(decisions, alpha=.05):
    if not 0 < alpha < 1:
        raise ValueError("alpha must be between zero and one")
    scores = defaultdict(list)
    for row in decisions:
        if row.get("partition") != "calibration":
            raise ValueError("Calibration accepts only the frozen calibration partition")
        if row.get("correct") is None:
            continue
        score = row["score"]
        if not 0 <= score <= 1:
            raise ValueError("Rank score out of range")
        scores[row["project"]].append(1 - score if row["correct"] else score)
    project_max = sorted(max(values) for values in scores.values())
    k = math.ceil((len(project_max) + 1) * (1 - alpha))
    q = project_max[k - 1] if k <= len(project_max) else None
    return {"schema_version": "project-conformal-v1", "alpha": alpha, "n_projects": len(project_max), "quantile": q,
            "score_interpretation": "ranking only, not a probability", "exchangeability": "UNVERIFIED_TEMPORAL_SHIFT",
            "coverage_guarantee_claim": "NONE_WITHOUT_EXCHANGEABILITY", "calibration_projects": sorted(scores)}


def prediction_set(model, score):
    q = model["quantile"]
    if q is None:
        return {"labels": ["SUPPORTED", "UNSUPPORTED"], "decision": "UNKNOWN"}
    labels = (["SUPPORTED"] if 1 - score <= q else []) + (["UNSUPPORTED"] if score <= q else [])
    return {"labels": labels, "decision": "SUPPORTED" if labels == ["SUPPORTED"] else "UNKNOWN"}


def extract_decisions(run_root, captures, destination, eligible_only=True):
    """Evaluation-only labeling. Default population: target-verified auto-apply proposals."""
    from .metrics import graph_facts, risk_coverage
    decisions = []
    for path in Path(run_root).rglob("records.json"):
        for row in load(path).get("records", []):
            if row.get("partition") != "calibration":
                raise ValueError("Decision labeling is restricted to the calibration partition")
            arm = path.parent / row["method"]
            if not (arm / "details.json").exists():
                continue
            result = load(arm / "details.json")
            verified = result.get("verified")
            if not verified:
                continue
            oracle = Path(captures) / row["project"] / "oracle"
            labels = load(oracle / "installed_field_labels.json")["fields"]
            reference = graph_facts(load(oracle / "installed_reference.cdx.json"))
            native = NativeDocument(load(path.parent / "input.spdx.json"))
            entities = NativeDocument(verified.get("document", native.data)).index()
            gold = load(oracle / "installed_reference.json")
            uncertain_names = {u.get("parent") for u in gold.get("unresolved", [])}
            uncertain_parents = {n["purl"] for n in gold["nodes"] if n["name"] in uncertain_names}
            proposals = result.get("proposals", [])
            for p in proposals:
                if isinstance(p, dict) and p.get("operation") == "add_component" and isinstance(p.get("value"), dict):
                    entities[p["subject"]] = p["value"]
            states = {sha(item["proposal"]): (state, item) for state in ("accepted", "supported", "rejected")
                      for item in verified.get(state, []) if isinstance(item.get("proposal"), dict)}
            for proposal in proposals:
                if not isinstance(proposal, dict):
                    continue
                state, _ = states.get(sha(proposal), ("rejected", {}))
                eligible = state == "accepted"
                if eligible_only and not eligible:
                    continue
                item = entities.get(proposal.get("subject"), {})
                name = canonicalize_name(item.get("name", ""))
                expected = labels.get(name, {})
                correct = None
                operation, value = proposal.get("operation"), proposal.get("value")
                if operation == "add_component":
                    purl = package_purl(value, native.format)
                    correct = purl in reference[0] if purl else False
                elif operation == "add_dependency":
                    source = package_purl(item, native.format)
                    target = package_purl(entities.get(value, {}), native.format) if isinstance(value, str) else None
                    correct = (source, target) in reference[1] if source and target else None
                    if source in uncertain_parents and (source, target) not in reference[1]:
                        correct = None
                elif operation == "set_field":
                    field = proposal.get("field")
                    if field in {"version", "versionInfo"}:
                        correct = value == expected["version"] if "version" in expected else None
                    elif field == "name":
                        correct = canonicalize_name(value) == expected["name"] if expected and isinstance(value, str) else None
                    elif field in {"purl", "externalRefs"}:
                        purl = value if field == "purl" else package_purl({"externalRefs": value}, "spdx")
                        try:
                            correct = canonical_purl(purl) == expected["purl"] if expected and purl else None
                        except (TypeError, ValueError):
                            correct = False
                    elif field in {"licenseDeclared", "licenses"} and "licenseDeclared" in expected:
                        if field == "licenses" and isinstance(value, list) and len(value) == 1:
                            value = value[0].get("expression") or value[0].get("license", {}).get("id")
                        correct = value == expected["licenseDeclared"]
                decisions.append({"project": row["project"], "partition": "calibration", "method": row["method"],
                                  "score": 1. if eligible else .5 if state == "supported" else 0.,
                                  "correct": correct, "eligible": eligible, "proposal_sha256": sha(proposal)})
    save(destination, decisions)
    save(str(destination) + ".risk-coverage.json", risk_coverage(decisions))
    return {"decisions": len(decisions), "known_labels": sum(d["correct"] is not None for d in decisions),
            "projects": len({d["project"] for d in decisions}),
            "population": "VERIFIED_TARGET auto-apply proposals" if eligible_only else "all proposals including unverified candidates"}
