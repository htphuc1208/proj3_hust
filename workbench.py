"""Build an offline Workbench from measured run bundles. No pipeline execution in the UI."""
import argparse
import json
import os
from pathlib import Path

from research_core import ROOT, digest, graph, load


def build(out, validation, controlled, ablation, reproduction):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    def link(path):
        return os.path.relpath(Path(path).resolve(), out)

    datasets = []
    for run, label in [(Path(validation), "Raw Syft · corrected scope"), (Path(controlled), "Controlled masking · real distributions")]:
        summary = load(run / "counterfactual_evidence_repair.json")
        for project in summary["projects"]:
            name = project["project"]
            original = load(run / name / "syft/original.cdx.json")
            scopes = load(run / name / "syft/scope.json")
            snapshots = {}
            for regime, record in project["regimes"].items():
                prediction = load(run / name / regime / "predictions.json")["B3"]
                manifest = load(run / "evidence_snapshot" / regime / "evidence_manifest.json")
                public = {f"pkg:pypi/{a['name']}@{a['version']}": load(run / "evidence_snapshot" / regime / a["metadata_file"]) for a in manifest["artifacts"]}
                snapshots[regime] = {"prediction": prediction, "scores": record["baselines"], "coverage": record["evidence_coverage"],
                    "public_evidence": public, "output": load(run / name / regime / "reconstructed.cdx.json"),
                    "links": {"SBOM": link(run / name / regime / "reconstructed.cdx.json"),
                              "Evidence": link(run / name / regime / "evidence.json"), "Evaluation": link(run / name / regime / "evaluation.json")}}
            datasets.append({"project": name, "label": label, "kind": summary["data_kind"], "snapshots": snapshots,
                "observed": load(run / name / "syft/normalized.cdx.json"), "scope": scopes,
                "raw_component_count": len(original.get("components", [])),
                "original_timestamp": original.get("metadata", {}).get("timestamp", "UNKNOWN"),
                "original_sha256": digest(run / name / "syft/original.cdx.json"),
                "positive_control": project["positive_control"], "manifest": load(run / "run_manifest.json"),
                "links": {"Raw generator SBOM": link(run / name / "syft/original.cdx.json"),
                          "Scope audit": link(run / "scope_audit.csv"), "Run manifest": link(run / "run_manifest.json"),
                          "Paired intervention": link(run / "counterfactual_evidence_repair.json")}})
    data = {"datasets": datasets, "ablation": load(Path(ablation) / "information_ablation_results.json"),
            "papers": load(Path(reproduction) / "reproduction_results.json"),
            "b4": load(Path(reproduction) / "b4_comparison.json"),
            "paper_links": {"Reproduction results": link(Path(reproduction) / "reproduction_results.json"),
                            "B4 predictions and evaluation": link(Path(reproduction) / "b4_comparison.json")}}
    payload = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    template = (ROOT / "workbench/template.html").read_text()
    (out / "index.html").write_text(template.replace("__RUN_DATA__", payload))
    (out / "build_manifest.json").write_text(json.dumps({"input_runs": list(map(str, [validation, controlled, ablation, reproduction])),
        "input_manifest_sha256": {str(p): digest(Path(p) / "run_manifest.json") for p in (validation, controlled, ablation, reproduction)},
        "output_sha256": digest(out / "index.html"), "interpretation": "Read-only presentation of stored measurements; no live experiment execution"}, indent=2))
    print(out / "index.html")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("out", "validation", "controlled", "ablation", "reproduction"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    build(a.out, a.validation, a.controlled, a.ablation, a.reproduction)
