"""Scorer-only sealed-oracle evaluation, separate from evidence acquisition.

Missing labels do not become negatives. Component precision is scored against
explicit absences or a declared complete reference domain. Duplicate unlocated
occurrences count separately, but cannot establish unambiguous edge endpoints.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import random
from statistics import mean

from .security import digest, identity, observed_paths


def _target(value):
    target = value.get("target", {})
    context = target.get("context_id", target.get("context", {}).get("context_id"))
    signature = (target.get("target_id"), target.get("revision_ref"), context, target.get("view"))
    if any(not isinstance(v, str) or not v for v in signature) or signature[-1] == "UNKNOWN":
        raise ValueError("Evaluation requires an explicit target, revision, context and view")
    return signature


def _label(row):
    if row.get("present") is False or row.get("status") in {"ABSENT", "REFUTED"}:
        return "ABSENT"
    if row.get("status") in {"UNKNOWN", "CONFLICT", "UNLABELED"} or row.get("present", True) is None:
        return "UNKNOWN"
    return "PRESENT"


def _key(row):
    ident = identity(row)
    if ident is None:
        # An oracle can label an observation whose identity is not known; that
        # is not sufficient to score exact identity correctness.
        return None
    return ("locator", row["locator"], *ident) if row.get("locator") is not None else ("identity", *ident)


def _index(rows):
    ids = [r.get("id") for r in rows]
    if any(not isinstance(i, str) or not i for i in ids) or len(ids) != len(set(ids)):
        raise ValueError("Component IDs must be unique nonempty strings")
    keys = {row["id"]: _key(row) for row in rows}
    counts = Counter(key for key in keys.values() if key is not None)
    # A repeated identity without a locator is an unresolved endpoint even
    # though its inventory multiplicity can still be scored.
    endpoints = {ref: key if key is not None and counts[key] == 1 else None for ref, key in keys.items()}
    return keys, endpoints


def _complete(oracle, domain):
    coverage = oracle.get("coverage", {})
    if not isinstance(coverage, dict):
        return False
    value = coverage.get(domain)
    return value is True or value == "COMPLETE"


def _prf(tp, fp, fn, **extra):
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return {"true_positive": tp, "false_positive": fp, "false_negative": fn,
            "precision": precision, "recall": recall, "f1": f1, **extra}


def _compare(predicted, present, absent, complete, unknown=None):
    true = predicted & present
    unmatched = predicted - present
    excluded = unmatched & (unknown or Counter())
    unmatched -= excluded
    false = unmatched if complete else unmatched & absent
    unscored = unmatched - false + excluded
    return _prf(sum(true.values()), sum(false.values()), sum((present - predicted).values()),
                unscored_predictions=sum(unscored.values()), labeled_positive=sum(present.values()),
                labeled_negative=sum(absent.values()), reference_complete=complete)


def _edges(rows, endpoints, default_supported=False, candidate=False):
    present, absent, unknown, unscored = Counter(), Counter(), Counter(), 0
    seen = set()
    for row in rows:
        status = _label(row) if default_supported else (
            "PRESENT" if row.get("status") == "SUPPORTED" or (candidate and row.get("status") != "REFUTED")
            else "ABSENT" if row.get("status") == "REFUTED" else "UNKNOWN")
        if status == "UNKNOWN" and not default_supported:
            continue
        source, target = endpoints.get(row.get("source")), endpoints.get(row.get("target"))
        if source is None or target is None:
            unscored += 1
            continue
        signature = (source, target, row.get("relationship_type", "direct_dependency"))
        # Repeated declarations are not repeated observations for scoring.
        key = (status, signature)
        if key not in seen:
            (present if status == "PRESENT" else absent if status == "ABSENT" else unknown)[signature] += 1
            seen.add(key)
    return present, absent, unknown, unscored


def _edge_scope(prediction, oracle, pred_endpoints, gold_endpoints, candidate=False):
    """Score labeled dependency scope independently from endpoint/type topology."""
    observed = defaultdict(set)
    for row in prediction.get("edges", []):
        if row.get("status") != "SUPPORTED" and not (candidate and row.get("status") != "REFUTED"):
            continue
        a, b = pred_endpoints.get(row.get("source")), pred_endpoints.get(row.get("target"))
        scope = row.get("scope")
        if a is not None and b is not None and scope not in (None, "unknown", "UNKNOWN", ""):
            observed[(a, b, row.get("relationship_type", "direct_dependency"))].add(
                json.dumps(scope, sort_keys=True, separators=(",", ":")))
    correct = incorrect = abstained = unscorable = 0
    seen = set()
    for row in oracle.get("edges", []):
        scope = row.get("scope")
        if _label(row) != "PRESENT" or scope in (None, "unknown", "UNKNOWN", ""):
            continue
        a, b = gold_endpoints.get(row.get("source")), gold_endpoints.get(row.get("target"))
        if a is None or b is None:
            unscorable += 1
            continue
        key = (a, b, row.get("relationship_type", "direct_dependency"))
        expected = json.dumps(scope, sort_keys=True, separators=(",", ":"))
        if (key, expected) in seen:
            continue
        seen.add((key, expected))
        actual = observed.get(key, set())
        if expected in actual:
            correct += 1
        elif actual:
            incorrect += 1
        else:
            abstained += 1
    total = correct + incorrect + abstained
    return {"correct": correct, "incorrect": incorrect, "abstained": abstained, "labeled": total,
            "unscorable": unscorable, "accuracy": correct / total if total else None,
            "decision_accuracy": correct / (correct + incorrect) if correct + incorrect else None}


def _paths(result, endpoints, oracle=False, candidate=False):
    normalized = dict(result)
    if oracle:
        normalized["components"] = [{**c, "status": "SUPPORTED" if _label(c) == "PRESENT" else "UNKNOWN"}
                                    for c in result.get("components", [])]
        normalized["edges"] = [{**e, "status": "SUPPORTED" if _label(e) == "PRESENT" else "UNKNOWN"}
                               for e in result.get("edges", [])]
    elif candidate:
        normalized["components"] = [{**c, "status": "SUPPORTED" if c.get("status") != "REFUTED" else "REFUTED"}
                                    for c in result.get("components", [])]
        normalized["edges"] = [{**e, "status": "SUPPORTED" if e.get("status") != "REFUTED" else "REFUTED"}
                               for e in result.get("edges", [])]
    out = Counter()
    for root in normalized.get("roots", []):
        # Security needs one witnessed path; path accuracy needs every
        # root/target pair, including targets reached from multiple roots.
        paths = observed_paths({**normalized, "roots": [root]})
        for ref, path in paths.items():
            if len(path) > 1 and endpoints.get(ref) is not None and endpoints.get(root) is not None:
                out[(endpoints[root], endpoints[ref])] = 1
    return out


def _fields(predicted_rows, oracle_rows):
    fields = ("ecosystem", "name", "version", "purl", "origin", "digest")
    pred = defaultdict(list)
    for row in predicted_rows:
        if row.get("status") == "SUPPORTED" and row.get("locator") is not None:
            pred[row["locator"]].append(row)
    gold = defaultdict(list)
    for row in oracle_rows:
        if _label(row) == "PRESENT" and row.get("locator") is not None:
            gold[row["locator"]].append(row)
    details = {}
    for field in fields:
        correct = incorrect = abstained = unscorable = 0
        for locator, rows in gold.items():
            if len(rows) != 1:
                unscorable += 1
                continue
            expected = rows[0].get(field)
            if expected is None:
                continue
            candidates = pred.get(locator, [])
            if len(candidates) != 1 or candidates[0].get(field) is None:
                abstained += 1
            elif candidates[0][field] == expected:
                correct += 1
            else:
                incorrect += 1
        total = correct + incorrect + abstained
        details[field] = {"correct": correct, "incorrect": incorrect, "abstained": abstained,
                          "labeled": total, "unscorable": unscorable,
                          "accuracy": correct / total if total else None,
                          "decision_accuracy": correct / (correct + incorrect) if correct + incorrect else None}
    return details


def _security(prediction, oracle, pred_keys, gold_keys):
    payload = oracle.get("security", {})
    labels = payload.get("labels", []) if isinstance(payload, dict) else payload
    if not labels:
        return {"status": "UNLABELED", "false_safe_rate": None, "incorrect_dismissal_rate": None,
                "candidate": {"status": "UNLABELED", **_prf(0, 0, 0)}}
    if isinstance(payload, dict) and payload.get("snapshot_sha256"):
        if prediction.get("security", {}).get("snapshot_sha256") != payload["snapshot_sha256"]:
            raise ValueError("Security scoring requires the same advisory snapshot")
    candidates = defaultdict(list)
    aliases = {}
    def occurrence(key):
        return key[:2] if key is not None and key[0] == "locator" else key
    for finding in prediction.get("security", {}).get("findings", []):
        component_key = occurrence(pred_keys.get(finding.get("component_id")))
        if component_key is not None:
            for advisory in set(finding.get("aliases", []) + [finding.get("advisory_id")]):
                candidates[(component_key, advisory)].append(finding)
                aliases[advisory] = min(finding.get("aliases", []) + [finding.get("advisory_id")])
    tp = fp = fn = unknown = false_safe = dismissed = affected_count = 0
    candidate_tp = candidate_fp = candidate_fn = 0
    seen = set()
    for row in labels:
        label = row.get("affected")
        component_key = occurrence(gold_keys.get(row.get("component_id")))
        if type(label) is not bool or component_key is None:
            unknown += 1
            continue
        signature = component_key, aliases.get(row.get("advisory_id"), row.get("advisory_id"))
        if signature in seen:
            continue
        seen.add(signature)
        findings = candidates.get((component_key, row.get("advisory_id")), [])
        positive = any(f.get("status") == "CONFIRMED_AFFECTED" for f in findings)
        candidate_positive = any(f.get("status") in {"CONFIRMED_AFFECTED", "POTENTIALLY_AFFECTED"} for f in findings)
        if label:
            affected_count += 1
            tp += int(positive)
            fn += int(not positive)
            candidate_tp += int(candidate_positive)
            candidate_fn += int(not candidate_positive)
            false_safe += int(any(f.get("status") in {"SAFE", "NOT_AFFECTED"} for f in findings))
            dismissed += int(any(f.get("status") in {"SAFE", "NOT_AFFECTED", "NOT_IN_AFFECTED_RANGE"} for f in findings))
        else:
            fp += int(positive)
            candidate_fp += int(candidate_positive)
    return {"status": "SCORED", **_prf(tp, fp, fn), "unlabeled": unknown,
            "false_safe_count": false_safe, "incorrect_dismissal_count": dismissed,
            "affected_labels": affected_count,
            "false_safe_rate": false_safe / affected_count if affected_count else None,
            "incorrect_dismissal_rate": dismissed / affected_count if affected_count else None,
            "candidate": {"status": "SCORED", **_prf(candidate_tp, candidate_fp, candidate_fn),
                          "interpretation": "Confirmed or potentially affected package assertions; no safety verdict"},
            "exploitability": "NOT_ASSESSED"}


def score(prediction, oracle):
    """Score only explicitly labeled, scope-compatible facts."""
    if oracle.get("schema_version") != "reconciliation-oracle-v1":
        raise ValueError("Expected reconciliation-oracle-v1")
    if _target(prediction) != _target(oracle):
        raise ValueError("Prediction and oracle target scopes differ")
    rows, gold = prediction.get("components", []), oracle.get("components", [])
    pred_keys, pred_endpoints = _index(rows)
    gold_keys, gold_endpoints = _index(gold)
    selected = Counter(pred_keys[r["id"]] for r in rows
                       if r.get("status") == "SUPPORTED" and pred_keys[r["id"]] is not None)
    candidates = Counter(pred_keys[r["id"]] for r in rows
                         if r.get("status") != "REFUTED" and pred_keys[r["id"]] is not None)
    positive = Counter(gold_keys[r["id"]] for r in gold
                       if _label(r) == "PRESENT" and gold_keys[r["id"]] is not None)
    negative = Counter(gold_keys[r["id"]] for r in gold
                       if _label(r) == "ABSENT" and gold_keys[r["id"]] is not None)
    unknown = Counter(gold_keys[r["id"]] for r in gold
                      if _label(r) == "UNKNOWN" and gold_keys[r["id"]] is not None)
    predicted_edges, _, _, pred_edge_unknown = _edges(prediction.get("edges", []), pred_endpoints)
    candidate_edges, _, _, _ = _edges(prediction.get("edges", []), pred_endpoints, candidate=True)
    gold_edges, absent_edges, unknown_edges, gold_edge_unknown = _edges(oracle.get("edges", []), gold_endpoints, True)
    predicted_paths, gold_paths = _paths(prediction, pred_endpoints), _paths(oracle, gold_endpoints, True)
    candidate_paths = _paths(prediction, pred_endpoints, candidate=True)
    absent_paths, unknown_paths = Counter(), Counter()
    for path in oracle.get("paths", []):
        a, b = gold_endpoints.get(path.get("source")), gold_endpoints.get(path.get("target"))
        if a is not None and b is not None:
            if path.get("present") is False:
                absent_paths[(a, b)] = 1
            elif path.get("present") is True:
                gold_paths[(a, b)] = 1
            else:
                unknown_paths[(a, b)] = 1
    coverage = Counter(r.get("status", "UNKNOWN") for r in rows)
    total = len(rows)
    corrections = []
    gold_by_locator = defaultdict(list)
    for row in gold:
        if _label(row) == "PRESENT" and row.get("locator") is not None:
            gold_by_locator[row["locator"]].append(row)
    for row in prediction.get("decisions", []):
        if row.get("disposition") != "APPLY" or row.get("operation") not in {"SET_FIELD", "SET_IDENTITY", "set_field"}:
            continue
        refs = gold_by_locator.get(row.get("locator"), [])
        field = row.get("field")
        if len(refs) == 1 and field and refs[0].get(field) is not None:
            corrections.append(row.get("value") == refs[0][field])
    security = _security(prediction, oracle, pred_keys, gold_keys)
    candidate_security = security.pop("candidate")
    return {"schema_version": "reconciliation-evaluation-v1", "target": oracle["target"],
            "oracle_sha256": digest(oracle), "prediction_sha256": digest(prediction),
            "components": _compare(selected, positive, negative, _complete(oracle, "components"), unknown),
            "candidate_components": _compare(candidates, positive, negative, _complete(oracle, "components"), unknown),
            "fields": _fields(rows, gold),
            "edges": _compare(predicted_edges, gold_edges, absent_edges, _complete(oracle, "edges"), unknown_edges),
            "candidate_edges": _compare(candidate_edges, gold_edges, absent_edges, _complete(oracle, "edges"), unknown_edges),
            "edge_scope": _edge_scope(prediction, oracle, pred_endpoints, gold_endpoints),
            "candidate_edge_scope": _edge_scope(prediction, oracle, pred_endpoints, gold_endpoints, candidate=True),
            "paths": _compare(predicted_paths, gold_paths, absent_paths, _complete(oracle, "paths"), unknown_paths),
            "candidate_paths": _compare(candidate_paths, gold_paths, absent_paths, _complete(oracle, "paths"), unknown_paths),
            "security": security, "candidate_security": candidate_security,
            "coverage": {"component_status_counts": dict(coverage), "component_count": total,
                         "verified_fraction": coverage["SUPPORTED"] / total if total else None,
                         "unknown_fraction": (coverage["UNKNOWN"] + coverage["CONFLICT"]) / total if total else None,
                         "oracle_unknown_components": sum(_label(r) == "UNKNOWN" for r in gold),
                         "unscorable_predicted_edges": pred_edge_unknown, "unscorable_oracle_edges": gold_edge_unknown},
            "corrections": {"scored": len(corrections), "incorrect": corrections.count(False),
                            "incorrect_rate": corrections.count(False) / len(corrections) if corrections else None},
            "interpretation": "Oracle labels are scorer-only; unlabeled facts do not become negatives"}


def score_files(prediction_path, oracle_path, out_path=None):
    """Evaluator entry point; inference must never import/call this function."""
    prediction_path, oracle_path = Path(prediction_path), Path(oracle_path)
    seal_path = prediction_path.parent / "seal.json"
    expected = None
    sealed_files = set()
    if seal_path.exists():
        if seal_path.is_symlink():
            raise ValueError("A prediction seal cannot be a symlink")
        seal = json.loads(seal_path.read_text())
        if seal.get("schema_version") != "investigation-seal-v1" or not isinstance(seal.get("files"), dict):
            raise ValueError("Invalid prediction seal")
        expected = seal["files"].get(prediction_path.name)
        if not isinstance(expected, str):
            raise ValueError("Prediction is missing from its seal")
        for name, frozen_digest in seal["files"].items():
            if not isinstance(name, str) or name != Path(name).name or name in {".", ".."}:
                raise ValueError("Unsafe sealed artifact name")
            path = prediction_path.parent / name
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != frozen_digest:
                raise ValueError("Sealed prediction artifact changed")
            sealed_files.add(path.resolve())
    raw = prediction_path.read_bytes()
    if prediction_path.is_symlink() or (expected is not None and hashlib.sha256(raw).hexdigest() != expected):
        raise ValueError("Prediction changed after sealing")
    # Only now may the evaluator open labels. Inference has already completed.
    result = score(json.loads(raw), json.loads(oracle_path.read_text()))
    result["seal_verified"] = expected is not None
    if out_path is not None:
        path = Path(out_path)
        if path.resolve() in sealed_files | {prediction_path.resolve(), oracle_path.resolve(), seal_path.resolve()}:
            raise ValueError("Scoring cannot overwrite predictions, labels or sealed artifacts")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def validate_splits(assignments):
    """A project and every recorded fork/lineage must belong to a single split."""
    projects, lineages = {}, {}
    for row in assignments:
        project, split = row.get("project_id"), row.get("split")
        lineage = row.get("lineage_id", project)
        if not all(isinstance(v, str) and v for v in (project, lineage, split)):
            raise ValueError("Split assignments require project, lineage and split")
        for index, key in ((projects, project), (lineages, lineage)):
            if key in index and index[key] != split:
                raise ValueError("Project/lineage leakage across splits")
            index[key] = split
    return {"projects": len(projects), "lineages": len(lineages), "valid": True}


def paired_bootstrap(rows, metric, left="P2", right="P4", samples=2000, seed=11):
    """Paired project-level mean delta (right minus left), after seed averaging."""
    if type(samples) is not int or samples < 1:
        raise ValueError("Bootstrap samples must be positive")
    grouped = defaultdict(list)
    for row in rows:
        value = row.get("metrics", {}).get(metric)
        if row.get("method") in {left, right} and type(value) in {int, float}:
            grouped[(row["project_id"], row["method"])].append(value)
    projects = sorted({p for p, method in grouped if (p, left) in grouped and (p, right) in grouped})
    if not projects:
        return {"metric": metric, "projects": 0, "delta": None, "ci95": None}
    deltas = [mean(grouped[(p, right)]) - mean(grouped[(p, left)]) for p in projects]
    generator = random.Random(seed)
    draws = sorted(mean(generator.choices(deltas, k=len(deltas))) for _ in range(samples))
    return {"metric": metric, "left": left, "right": right, "projects": len(projects),
            "delta": mean(deltas), "ci95": [draws[int((samples - 1) * .025)], draws[int((samples - 1) * .975)]],
            "samples": samples, "seed": seed, "unit": "project", "repeated_runs": "averaged_within_project"}
