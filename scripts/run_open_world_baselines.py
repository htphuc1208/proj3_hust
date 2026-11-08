#!/usr/bin/env python3
"""Offline B5 topology audit and optional frozen B6 comparison. New bundles only."""
import argparse
from collections import Counter, defaultdict
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from depsdev_baseline import b6_from_response
from graph_triage import b5_assess
from research_core import RunBundle, digest, graph, load, score_application


REFERENCES = {"requests": "runs/e4-generator-discrepancy/ground_truth.json",
              "requests-cache": "runs/pilot-repo-requests-cache/reference/ground_truth.json",
              "httpbin": "runs/pilot-repo-httpbin/reference/ground_truth.json"}
DEFAULT_RUNS = {"raw": "runs/m23-validation-v2", "controlled": "runs/m23-controlled-repair-v2",
                "dsn": "runs/m23-dsn-b4-v2"}


def observed_inputs(raw, controlled, dsn):
    for path in sorted(Path(raw).glob("*/syft/original.cdx.json")):
        project = path.parent.parent.name
        for generator in ("syft", "cyclonedx"):
            for view in ("original", "normalized"):
                yield "raw", project, generator, view, Path(raw) / project / generator / f"{view}.cdx.json"
        for regime in ("partial", "wheel", "sdist"):
            yield "raw", project, "B3", regime, Path(raw) / project / regime / "reconstructed.cdx.json"
        yield "controlled", project, "syft", "normalized", Path(controlled) / project / "syft/normalized.cdx.json"
        for regime in ("partial", "wheel", "sdist"):
            yield "controlled", project, "B3", regime, Path(controlled) / project / regime / "reconstructed.cdx.json"
    for case in ("requirements", "r", "positive_control"):
        for generator in ("syft", "trivy"):
            yield "synthetic_parser_control" if case == "positive_control" else "dsn_authored_metadata", case, generator, "original", Path(dsn) / case / f"{generator}.cdx.json"


def run(out, raw, controlled, dsn, depsdev_snapshot=None):
    bundle = RunBundle(out, Path(out).name, purpose="B5 declared graph audit and B6 separate remote candidate comparison",
                       data_kind="SEPARATE_RAW_CONTROLLED_AND_AUTHORED_METADATA_TRACKS", seed=None,
                       installation_time="UNKNOWN", no_model_api_calls=True)
    bundle.data["protocol"] = "m2.4-open-world-v1"
    rows, aggregates = [], defaultdict(Counter)
    try:
        for track, project, generator, view, path in observed_inputs(raw, controlled, dsn):
            document = load(path)
            started = time.perf_counter()
            result = b5_assess(document)
            result["duration_seconds"] = time.perf_counter() - started
            key = f"b5/{track}/{project}/{generator}/{view}.json"
            bundle.artifact(key, result)
            row = {"track": track, "project": project, "generator": generator, "view": view,
                   "source": str(path.relative_to(ROOT)), "source_sha256": digest(path),
                   "source_sbom_timestamp": document.get("metadata", {}).get("timestamp", "UNKNOWN"),
                   "assessment_file": key, "topology": result["topology"], "counts": result["counts"],
                   "duration_seconds": result["duration_seconds"]}
            rows.append(row)
            aggregates[f"{track}/{generator}/{view}"][result["topology"]["regime"]] += 1
        bundle.artifact("b5_results.json", {"baseline_id": "B5", "records": rows,
            "regime_counts_by_track_and_representation": dict(aggregates),
            "documents": len(rows), "independent_project_count": 3,
            "population_inference": "NONE; repeated representations are paired observations, not independent projects",
            "paper_reproduction": "LOCAL_TAXONOMY_ADAPTATION; author scanner/dataset not obtained",
            "downstream_metrics": {"vrr": None, "openvex_triage_delta": None, "false_assurance_reduction": None,
                                   "status": "UNMEASURED_NO_INDEPENDENT_ADVISORY_OR_PRODUCT_LABELS"}})
        b6 = []
        if depsdev_snapshot:
            snapshot = Path(depsdev_snapshot)
            acquisition = load(snapshot / "acquisition.json")
            bundle.copy("depsdev/acquisition.json", snapshot / "acquisition.json")
            for query in acquisition["queries"]:
                if query["status"] != "AVAILABLE":
                    b6.append({**query, "status": "UNAVAILABLE", "prediction": None, "evaluation": None})
                    continue
                response_file = (snapshot / query["response_file"]).resolve()
                if not response_file.is_relative_to(snapshot.resolve()):
                    raise ValueError("Response path escapes snapshot")
                if digest(response_file) != query["response_sha256"]:
                    raise ValueError("Remote response digest mismatch")
                project = query["project"]
                document = load(Path(raw) / project / "syft/normalized.cdx.json")
                observed_root = document.get("metadata", {}).get("component", {}).get("purl")
                if observed_root != query["root_purl"]:
                    raise ValueError("Remote query seed does not match observed root")
                context = {"os": "Linux", "arch": "x86_64", "python_full_version": "3.11.16", "active_extras": []}
                prediction = b6_from_response(load(response_file), query["root_purl"], query, context)
                # Oracle is opened only AFTER the remote prediction is complete.
                gold_path = ROOT / REFERENCES[project]
                gold = load(gold_path)
                _, observed = graph(document)
                evaluation = score_application(gold, observed, set(map(tuple, prediction["predicted_edges"])),
                                               load(Path(raw) / project / "syft/scope.json"))
                bundle.copy(f"depsdev/responses/{project}.json", response_file)
                bundle.artifact(f"b6/{project}/prediction.json", prediction)
                bundle.artifact(f"b6/{project}/evaluation.json", evaluation)
                b6.append({"project": project, "status": prediction["status"], "prediction": prediction,
                           "evaluation": evaluation, "oracle_source": REFERENCES[project], "oracle_sha256": digest(gold_path)})
        bundle.artifact("b6_results.json", {"baseline_id": "B6", "status": "EXECUTED" if depsdev_snapshot else "NOT_RUN",
            "records": b6, "snapshot": str(depsdev_snapshot) if depsdev_snapshot else None,
            "interpretation": "Separate remote information budget; exact remote versions, environment/time mismatch explicit. No target graph merge."})
        bundle.finish()
        print({"B5_documents": len(rows), "B6_queries": len(b6), "out": str(out)})
    except Exception as exc:
        bundle.finish("FAILED", error=str(exc))
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    for name, default in DEFAULT_RUNS.items():
        parser.add_argument("--" + name, type=Path, default=ROOT / default)
    parser.add_argument("--depsdev-snapshot", type=Path)
    args = parser.parse_args()
    run(args.out, args.raw, args.controlled, args.dsn, args.depsdev_snapshot)
