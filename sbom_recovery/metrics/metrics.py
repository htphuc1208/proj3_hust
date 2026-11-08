"""Independent scoring. Unknown labels are not negatives; repeats are not new projects."""
from __future__ import annotations

from collections import defaultdict, deque
from copy import deepcopy
import math
import random

from packaging.utils import canonicalize_name
from sbom_recovery.core.formats import NativeDocument, encoded, package_purl
from sbom_recovery.core.scope import installed_candidates
from sbom_recovery.core.research_core import score_sets


def graph_facts(document):
    native = NativeDocument(document)
    candidates, _ = installed_candidates(document)
    identities = {r: package_purl(i, native.format) for r, i in candidates.items()}
    nodes = {p for p in identities.values() if p}
    edges = {(identities[s], identities[t]) for s, t in native.edges() if identities.get(s) and identities.get(t)}
    return nodes, edges


def metadata_facts(document):
    native = NativeDocument(document)
    facts = set()
    candidates, _ = installed_candidates(document)
    for ref, item in native.packages().items():
        if not package_purl(item, native.format) and item.get("name") and not any(
                k in item.get("sourceInfo", "") for k in ("/_vendor/", "/vendored/", "/tests/data/")):
            candidates[ref] = item
    for _, item in candidates.items():
        name = canonicalize_name(item.get("name", ""))
        values = {"name": name, "version": item.get("version", item.get("versionInfo")),
                  "purl": package_purl(item, native.format), "licenseDeclared": item.get("licenseDeclared")}
        if native.format == "cyclonedx":
            licenses = item.get("licenses", [])
            if len(licenses) == 1:
                values["licenseDeclared"] = licenses[0].get("expression") or licenses[0].get("license", {}).get("id")
        for field, value in values.items():
            if value and value not in ("NOASSERTION", "NONE"):
                facts.add((name, field, encoded(value).decode()))
    return facts


def evaluate(reference, observed, predicted, field_labels=None, unresolved_parents=(), bootstrap_names=()):
    tn, te = graph_facts(reference)
    on, oe = graph_facts(observed)
    pn, pe = graph_facts(predicted)
    # Provisioning scope is declared by the harness. Exclude only exact observed tool identities
    # absent from the application reference; new erroneous tool versions are still counted.
    from packageurl import PackageURL
    bootstrap = {p for p in on if PackageURL.from_string(p).name in bootstrap_names and p not in tn}
    on -= bootstrap; pn -= bootstrap
    oe = {e for e in oe if e[0] not in bootstrap}
    pe = {e for e in pe if e[0] not in bootstrap}
    unknown = {e for e in pe if e[0] in unresolved_parents and e not in te}
    pe -= unknown
    result = {"whole_nodes": score_sets(tn, pn), "new_nodes": score_sets(tn - on, pn - on),
              "whole_edges": score_sets(te, pe), "new_edges": score_sets(te - oe, pe - oe),
              "unknown_label_edges": sorted(map(list, unknown)), "unknown_label_edge_count": len(unknown),
              "false_positive_edges": sorted(map(list, pe - te)), "missed_edges": sorted(map(list, te - pe)),
              "false_positive_nodes": sorted(pn - tn), "missed_nodes": sorted(tn - pn)}
    result["scope_audit"] = {"observed": installed_candidates(observed)[1], "predicted": installed_candidates(predicted)[1],
                             "excluded_exact_bootstrap_purls": sorted(bootstrap)}
    if field_labels is not None:
        labels = {(canonicalize_name(name), field, encoded(value).decode())
                  for name, fields in field_labels.items() for field, value in fields.items()}
        known_keys = {(n, f) for n, f, _ in labels}
        obs, pred = metadata_facts(observed), metadata_facts(predicted)
        result["unlabeled_metadata_facts"] = len({f for f in pred if f[:2] not in known_keys})
        obs, pred = {f for f in obs if f[:2] in known_keys}, {f for f in pred if f[:2] in known_keys}
        result["whole_metadata"] = score_sets(labels, pred)
        result["new_metadata"] = score_sets(labels - obs, pred - obs)
        result["false_positive_metadata"] = sorted(map(list, pred - labels))
        result["missed_metadata"] = sorted(map(list, labels - pred))
    else:
        result.update(whole_metadata=None, new_metadata=None, metadata_status="UNMEASURED_NO_FIELD_LABELS")
    errors = []
    for unit, false_positive, false_negative in (
            ("node", "false_positive_nodes", "missed_nodes"),
            ("direct_edge", "false_positive_edges", "missed_edges"),
            ("metadata_fact", "false_positive_metadata", "missed_metadata")):
        for direction, field in (("FP", false_positive), ("FN", false_negative)):
            errors.extend({"unit": unit, "direction": direction, "fact": item,
                           "attribution": "UNRESOLVED_NO_CAUSAL_EVIDENCE"} for item in result.get(field, []))
    result["failure_taxonomy"] = {"A": [], "B": [], "C": [], "D": [], "E": [], "UNRESOLVED": errors}
    result["failure_taxonomy_counts"] = {key: len(values) for key, values in result["failure_taxonomy"].items()}
    result["downstream"] = {"vrr": None, "triage_delta": None, "false_assurance_reduction": None,
                              "status": "UNMEASURED_WITHOUT_INDEPENDENT_ADVISORY_AND_PRODUCT_LABELS"}
    return result


def controlled_mask(document, rate, seed, family):
    if not 0 <= rate <= 1 or family not in {"component", "metadata", "dependency"}:
        raise ValueError("Invalid masking parameters")
    native = NativeDocument(document)
    rng = random.Random(seed)
    removed = []
    if family == "dependency":
        # Remove whole source declarations; never replace unknown with an explicit zero.
        if native.format == "cyclonedx":
            rows = native.data.get("dependencies", [])
            selected = set(rng.sample(range(len(rows)), round(len(rows) * rate)))
            removed = [r for i, r in enumerate(rows) if i in selected]
            native.data["dependencies"] = [r for i, r in enumerate(rows) if i not in selected]
        else:
            rows = native.data.get("relationships", [])
            indices = [i for i, r in enumerate(rows) if r.get("relationshipType") in {"DEPENDS_ON", "DEPENDENCY_OF"}]
            selected = set(rng.sample(indices, round(len(indices) * rate)))
            removed = [r for i, r in enumerate(rows) if i in selected]
            native.data["relationships"] = [r for i, r in enumerate(rows) if i not in selected]
    elif family == "metadata":
        fields = {"version", "versionInfo", "purl", "externalRefs", "licenses", "licenseDeclared", "hashes", "checksums"}
        positions = [(ref, field) for ref, item in native.packages().items() for field in sorted(fields) if field in item]
        for ref, field in rng.sample(positions, round(len(positions) * rate)):
            removed.append({"ref": ref, "field": field, "value": native.index()[ref].pop(field)})
    else:
        key = "components" if native.format == "cyclonedx" else "packages"
        rows = native.data.get(key, [])
        # Keep the declared root. Node loss and incident-edge loss are recorded together.
        root_refs = {r.get("relatedSpdxElement") for r in native.data.get("relationships", []) if r.get("relationshipType") == "DESCRIBES"}
        candidates = [i for i, r in enumerate(rows) if r.get(native.id_field) not in root_refs]
        selected = set(rng.sample(candidates, round(len(candidates) * rate)))
        removed = [r for i, r in enumerate(rows) if i in selected]
        refs = {r.get(native.id_field) for r in removed}
        native.data[key] = [r for i, r in enumerate(rows) if i not in selected]
        if native.format == "cyclonedx":
            native.data["dependencies"] = [{**r, "dependsOn": [t for t in r.get("dependsOn", []) if t not in refs]}
                for r in native.data.get("dependencies", []) if r.get("ref") not in refs]
        else:
            native.data["relationships"] = [r for r in native.data.get("relationships", [])
                if r.get("spdxElementId") not in refs and r.get("relatedSpdxElement") not in refs]
    return native.data, {"family": family, "rate": rate, "seed": seed, "mechanism": "CONTROLLED_MCAR",
                         "removed": removed, "interpretation": "Pipeline stress test; not evidence of MNAR performance"}


def paired_bootstrap(rows, method, baseline, metric, repetitions=10000, seed=42):
    # Average all masks/repetitions within a project before resampling independent roots.
    cases = defaultdict(lambda: defaultdict(list))
    for r in rows:
        value = r.get("metrics", {}).get(metric)
        if value is not None and r["method"] in (method, baseline):
            key = (r["project"], *(r.get(k) for k in ("condition", "budget", "family", "rate", "mask_seed", "repetition", "input_origin")))
            cases[key][r["method"]].append(value)
    project_values = defaultdict(list)
    for key, values in cases.items():
        if values[method] and values[baseline]:
            project_values[key[0]].append(sum(values[method]) / len(values[method]) - sum(values[baseline]) / len(values[baseline]))
    pairs = [sum(values) / len(values) for values in project_values.values()]
    if not pairs:
        return {"status": "UNMEASURED_NO_PAIRED_PROJECTS", "n_projects": 0}
    import numpy as np
    rng = np.random.default_rng(seed)
    values = np.asarray(pairs)
    samples = np.mean(rng.choice(values, size=(repetitions, len(values)), replace=True), axis=1)
    # Paired randomization, clustered by project. Zero differences remain zero.
    null = np.mean(values * rng.choice([-1, 1], size=(repetitions, len(values))), axis=1)
    p = float((1 + np.count_nonzero(np.abs(null) >= abs(values.mean()))) / (repetitions + 1))
    return {"status": "MEASURED", "method": method, "baseline": baseline, "metric": metric,
            "n_projects": len(pairs), "mean_delta": float(values.mean()),
            "ci95": [float(x) for x in np.quantile(samples, [0.025, 0.975])], "p_value": p,
            "bootstrap_unit": "project", "repetitions": repetitions}


def holm(results):
    valid = sorted([r for r in results if "p_value" in r], key=lambda x: x["p_value"])
    maximum = 0.0
    for i, row in enumerate(valid):
        maximum = max(maximum, min(1., row["p_value"] * (len(valid) - i)))
        row["p_holm"] = maximum
    return results


def risk_coverage(scored_decisions):
    # Scores are rankings, never advertised as probabilities. Unknown labels cannot be losses.
    known = [r for r in scored_decisions if r.get("correct") in (True, False)]
    unknown = len(scored_decisions) - len(known)
    rows = []
    for threshold in sorted({r["score"] for r in known}, reverse=True):
        accepted = [r for r in known if r["score"] >= threshold]
        rows.append({"threshold": threshold, "coverage": len(accepted) / len(known),
                     "selective_risk": sum(not r["correct"] for r in accepted) / len(accepted)})
    return {"curve": rows, "known_labels": len(known), "unknown_labels": unknown,
            "calibration": "UNMEASURED_RANK_SCORES_ONLY"}
