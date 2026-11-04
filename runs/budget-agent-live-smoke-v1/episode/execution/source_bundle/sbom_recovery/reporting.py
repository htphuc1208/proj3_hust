"""Artifact-backed research reports; keep scope, budgets and partitions separate."""
from collections import Counter, defaultdict
import csv
import io
import json
from pathlib import Path

from research_core import digest, load, now
from .storage import save, save_bytes

GROUP = ("partition", "condition", "budget", "family", "rate", "input_origin", "method", "model")
SCORES = {"new_nodes": "new_node", "whole_nodes": "whole_node",
          "new_edges": "new_direct_edge", "whole_edges": "whole_direct_edge",
          "new_metadata": "new_metadata", "whole_metadata": "whole_metadata"}


def read_records(run_root):
    records, provenance = [], {}
    for path in sorted(Path(run_root).rglob("records.json")):
        provenance[str(path)] = digest(path)
        for original in load(path).get("records", []):
            row = dict(original)
            row.setdefault("input_origin", "LEGACY_SCANNER_INPUT")
            metrics = dict(row.get("metrics", {}))
            arm = path.parent / row["method"]
            evaluation = load(arm / "evaluation.json") if (arm / "evaluation.json").exists() else {}
            for source, target in SCORES.items():
                for measure in ("precision", "recall", "f1"):
                    metrics[f"{target}_{measure}"] = (evaluation.get(source) or {}).get(measure, metrics.get(f"{target}_{measure}"))
            details = load(arm / "details.json") if (arm / "details.json").exists() else {}
            verified, tokens = details.get("verified", {}), details.get("tokens", {})
            row.update(metrics=metrics, tool_calls=len(details.get("tool_trace", [])),
                proposal_count=len(details.get("proposals", [])),
                accepted=len(verified.get("accepted", [])), supported=len(verified.get("supported", [])),
                rejected=len(verified.get("rejected", [])),
                unsupported_blocked=sum(p.get("reason") == "NO_SUPPORTING_FACT" for p in verified.get("rejected", [])),
                reported_tokens=tokens.get("total_tokens", 0), unknown_usage_attempts=tokens.get("unknown_usage_attempts", 0),
                unknown_label_edges=evaluation.get("unknown_label_edge_count", 0),
                unlabeled_metadata_facts=evaluation.get("unlabeled_metadata_facts", 0))
            validity = load(arm / "validation.json") if (arm / "validation.json").exists() else None
            row["validation"] = validity.get("valid") if validity else None
            for category in ("A", "B", "C", "D", "E", "UNRESOLVED"):
                row["failure_" + category] = len(evaluation.get("failure_taxonomy", {}).get(category, []))
            for unit, fp, fn in (("nodes", "false_positive_nodes", "missed_nodes"),
                                 ("edges", "false_positive_edges", "missed_edges"),
                                 ("metadata", "false_positive_metadata", "missed_metadata")):
                row[unit + "_fp"] = len(evaluation.get(fp, []))
                row[unit + "_fn"] = len(evaluation.get(fn, []))
            if (arm / "security.json").exists():
                security = load(arm / "security.json")
                metrics.update(vrr_before=security["vrr_before"], vrr_after=security["vrr_after"])
                row["security_assessed"] = True
            records.append(row)
    return records, provenance


def aggregate(records):
    groups = defaultdict(list)
    for row in records:
        groups[tuple(row.get(key) for key in GROUP)].append(row)
    rows = []
    for key, items in sorted(groups.items(), key=lambda item: tuple(str(k) for k in item[0])):
        result = dict(zip(GROUP, key))
        statuses = Counter(r.get("status", "UNRECORDED") for r in items)
        result.update(projects=len({r["project"] for r in items}), cases=len(items),
            incomplete=sum(n for status, n in statuses.items() if status != "COMPLETE"),
            status_counts=json.dumps(dict(sorted(statuses.items())), sort_keys=True),
            llm_api_calls=sum(r.get("llm_api_calls", 0) for r in items),
            duration_seconds=sum(r.get("duration_seconds") or 0 for r in items),
            missing_duration_cases=sum(r.get("duration_seconds") is None for r in items),
            validation_passed=sum(r["validation"] is True for r in items),
            validation_failed=sum(r["validation"] is False for r in items),
            validation_unmeasured=sum(r["validation"] is None for r in items),
            monetary_cost="UNMEASURED_NO_VERIFIED_PROVIDER_PRICING")
        for field in ("tool_calls", "proposal_count", "accepted", "supported", "rejected", "unsupported_blocked",
                      "reported_tokens", "unknown_usage_attempts", "unknown_label_edges", "unlabeled_metadata_facts",
                      "failure_A", "failure_B", "failure_C", "failure_D", "failure_E", "failure_UNRESOLVED",
                      "nodes_fp", "nodes_fn", "edges_fp", "edges_fn", "metadata_fp", "metadata_fn"):
            result[field] = sum(r[field] for r in items)
        for metric in [f"{prefix}_{measure}" for prefix in SCORES.values() for measure in ("precision", "recall", "f1")] + ["vrr_before", "vrr_after"]:
            by_project = defaultdict(list)
            for row in items:
                value = row["metrics"].get(metric)
                if value is not None:
                    by_project[row["project"]].append(value)
            means = [sum(values) / len(values) for values in by_project.values()]
            result[metric] = sum(means) / len(means) if means else None
            result[metric + "_n_projects"] = len(means)
        rows.append(result)
    return rows


def figures(rows, destination):
    if not rows:
        return []
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    files = []
    panels = sorted({(r["partition"], r["condition"], r["budget"]) for r in rows})
    for partition, condition, budget in panels:
        subset = [r for r in rows if (r["partition"], r["condition"], r["budget"]) == (partition, condition, budget)]
        labels = sorted({(r["family"], r["rate"]) for r in subset})
        methods = sorted({r["method"] + (" / " + r["model"] if r["model"] else "") for r in subset})
        fig, axes = plt.subplots(1, 2, figsize=(max(11, len(methods) * 1.35), max(3.5, len(labels) * .42 + 2)))
        for ax, metric, title in zip(axes, ("new_metadata_f1", "new_direct_edge_f1"), ("New metadata", "New direct edges")):
            values = np.full((len(labels), len(methods)), np.nan)
            for row in subset:
                name = row["method"] + (" / " + row["model"] if row["model"] else "")
                if row[metric] is not None:
                    values[labels.index((row["family"], row["rate"]))][methods.index(name)] = row[metric]
            cmap = plt.get_cmap("viridis").copy(); cmap.set_bad("#dddddd")
            im = ax.imshow(np.ma.masked_invalid(values), vmin=0, vmax=1, cmap=cmap, aspect="auto")
            ax.set_xticks(range(len(methods)), methods, rotation=35, ha="right", fontsize=8)
            ax.set_yticks(range(len(labels)), [f"{f} / {r:g}" for f, r in labels], fontsize=8)
            ax.set_title(title + " — project-macro F1")
            fig.colorbar(im, ax=ax, fraction=.035)
        fig.suptitle(f"{partition} / {condition} / tool budget {budget}; gray = undefined or unmeasured")
        fig.tight_layout()
        for suffix in ("svg", "pdf"):
            path = destination / f"f1-{partition}-{condition}-budget-{budget}.{suffix}"
            fig.savefig(path); files.append(str(path))
        plt.close(fig)
    return files


def report(run_root, destination):
    run_root, destination = Path(run_root), Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    records, provenance = read_records(run_root)
    rows = aggregate(records)
    if rows:
        text = io.StringIO()
        writer = csv.DictWriter(text, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
        save_bytes(destination / "metrics.csv", text.getvalue().encode())
    plots = figures(rows, destination)
    incomplete = sum(r.get("status") != "COMPLETE" for r in records)
    assessed = sum(r.get("security_assessed", False) for r in records)
    sections = [
        "# Evidence-grounded SBOM recovery — executed artifacts",
        "## Context & Problem Formulation\nRecover native fields and environment-conditioned declared package dependencies. The reference covers top-level installed distributions. Package paths are Level 1 evidence; runtime call paths and exploitability are unmeasured.",
        "## Theoretical Background & Sourcing\nMoriwaki et al. (2026), sbom-unifier, ICSME Tool Demonstrations: https://arxiv.org/abs/2608.30708. The original 39-field analyzer measures presence, not correctness. PyPA dependency semantics: https://packaging.python.org/en/latest/specifications/dependency-specifiers/. SPDX 2.3: https://spdx.github.io/spdx-spec/v2.3/. Source coverage and installed correctness have separate populations.",
        "## Hypothesis & Experimental Design\nFixed evidence and active acquisition, tool budgets, mask families/rates and chronological partitions have separate rows. Seeds and LLM repetitions are averaged within project; they are not independent projects. Predictions are sealed before oracle scoring. Controlled masks are MCAR stress tests; raw scanner discrepancies are not automatically MNAR. Improvement over sbom-unifier alone does not isolate AI contribution; inspect the deterministic controls with the same evidence.",
        "## Empirical Evidence & Downstream Metrics\n" + f"Generated {now()}. Recorded {len(records)} arm observations across {len({r['project'] for r in records})} projects, including {incomplete} incomplete/failed arms. See metrics.csv, per-arm evaluations, seals and grouped summary.json. Null scores retain undefined denominators, and each metric reports its eligible project count. Tokens are provider-reported; missing usage and monetary costs are explicit. {assessed} arms have retrospective OSV Level 1 assessments. Product-level VEX triage delta, false-assurance reduction and exploitability remain unmeasured. This report may describe a running checkpoint; it is not evidence that the registered matrix has finished.",
        "## Failure Taxonomy & Threats to Validity\nTaxonomy A–E is recorded in per-arm evaluations; unresolved attribution remains UNRESOLVED. Missing paths remain UNKNOWN. Pure-Python root selection, dependency-size exclusions, one Linux/CPython environment, shared dependencies, retrospective availability constraints and unknown model pretraining contamination limit generalization. Target metadata may be sufficient for deterministic recovery. A rejected unsupported proposal is a blocked attempt, not a false fact committed to the SBOM.",
        "## Actionable Next Steps\nConsult the controller state and expected case counts before treating a checkpoint as final. Assess project-paired confidence intervals, Holm-adjusted comparisons against the original unifier and equal-evidence deterministic controls, failure statuses and acquisition costs. Preserve negative and equivalent results. Any broader security claim requires independent product/runtime evidence."
    ]
    save_bytes(destination / "REPORT.md", ("\n\n".join(sections) + "\n").encode())
    save(destination / "report.json", {"generated_at": now(), "records": len(records), "groups": rows,
         "record_sha256": provenance, "figures": plots, "security_assessed_arms": assessed,
         "superiority": "NOT_ESTABLISHED_AUTOMATICALLY"})
    return {"records": len(records), "groups": len(rows), "report": str(destination / "REPORT.md")}
