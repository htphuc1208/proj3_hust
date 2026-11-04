"""Freeze model choice exclusively from complete development experiments."""
from collections import defaultdict
from pathlib import Path

from research_core import digest, load, now, save
from .storage import save


def select_scanner(captures, cohort):
    from .scope import installed_view
    from .metrics import evaluate
    scores = defaultdict(list)
    for project in cohort["projects"]:
        if project["partition"] != "development":
            continue
        root = Path(captures) / project["name"]
        reference = load(root / "oracle/installed_reference.cdx.json")
        fields = load(root / "oracle/installed_field_labels.json")["fields"]
        for scanner in ("syft", "trivy"):
            path = root / "runtime" / (scanner + ".spdx.json")
            if not path.exists():
                scores[scanner].append(0.)
                continue
            observed, _ = installed_view(load(path))
            result = evaluate(reference, observed, observed, fields)
            values = [result[k]["f1"] for k in ("whole_nodes", "whole_edges", "whole_metadata") if result[k]["f1"] is not None]
            scores[scanner].append(sum(values) / len(values) if values else 0.)
    candidates = [{"scanner": scanner, "mean_f1": sum(values) / len(values), "projects": len(values)}
                  for scanner, values in scores.items()]
    candidates.sort(key=lambda r: (-r["mean_f1"], r["scanner"]))
    return {"scanner": candidates[0]["scanner"], "candidates": candidates,
            "scope": "20 development projects only; no per-test-project selection"}


def select_model(run_roots, cohort_file, destination, captures=None):
    cohort = load(cohort_file)
    expected = {r["name"] for r in cohort["projects"] if r["partition"] == "development"}
    rows, provenance = [], {}
    for root in run_roots:
        campaign = load(Path(root) / "campaign.json")
        if campaign.get("status") not in {"COMPLETE", "PARTIAL"} or campaign["settings"]["phase"] != "development":
            raise ValueError("Model selection requires finished development campaigns, including explicit failure records")
        for path in Path(root).rglob("records.json"):
            provenance[str(path)] = digest(path)
            for row in load(path).get("records", []):
                if row.get("partition") != "development":
                    raise ValueError("Model selection input contains non-development observations")
                if row["method"] == "single_agent":
                    arm = path.parent / row["method"]
                    seal = load(arm / "seal.json")
                    if digest(arm / "prediction.spdx.json") != seal["prediction_sha256"]:
                        raise ValueError("Development prediction changed after sealing")
                    rows.append(row)
    case_sets = defaultdict(set)
    for row in rows:
        key = tuple(row.get(k) for k in ("project", "condition", "budget", "family", "rate", "mask_seed", "repetition"))
        if key in case_sets[row["model"]]:
            raise ValueError("Duplicate model/case observations in model selection")
        case_sets[row["model"]].add(key)
    if len({frozenset(cases) for cases in case_sets.values()}) > 1:
        raise ValueError("Models were not evaluated on the same complete case matrix")
    scores = defaultdict(lambda: defaultdict(list))
    projects = defaultdict(set)
    for row in rows:
        model = row["model"]
        projects[model].add(row["project"])
        for metric in ("new_metadata_f1", "new_direct_edge_f1"):
            value = row.get("metrics", {}).get(metric)
            if value is not None:
                scores[model][(row["project"], metric)].append(value)
    candidates = []
    for model, values in scores.items():
        if projects[model] != expected:
            continue
        project_metric_means = [sum(v) / len(v) for v in values.values()]
        candidates.append({"model": model, "score": sum(project_metric_means) / len(project_metric_means),
                           "n_projects": len(projects[model])})
    if not candidates:
        raise ValueError("No model has results on all 20 development projects; selection remains unfrozen")
    candidates.sort(key=lambda r: (-r["score"], r["model"]))
    result = {"status": "FROZEN", "model": candidates[0]["model"], "cohort_sha256": digest(cohort_file),
              "selected_at": now(), "criterion": "mean project/metric F1 on development; lexicographic ID tie break",
              "candidates": candidates, "development_artifacts_sha256": provenance, "test_labels_used": False}
    if captures:
        result["scanner_selection"] = select_scanner(captures, cohort)
        result["single_scanner"] = result["scanner_selection"]["scanner"]
    else:
        result["single_scanner"] = "syft"
        result["scanner_selection"] = "PREDECLARED_SYFT; not selected using test labels"
    if Path(destination).exists():
        raise FileExistsError("Model selection is immutable; use a new campaign")
    save(destination, result)
    return result
