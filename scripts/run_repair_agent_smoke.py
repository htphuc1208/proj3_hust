#!/usr/bin/env python3
"""Run the scripted proposal/tool/verifier prototype without oracle/network mounts."""
import argparse
from pathlib import Path
import shutil
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from container_runner import run_container
from research_core import RunBundle, digest, graph, load, now, reconstructed_document, save, score_application, validate_cdx
from scripts.run_open_world_baselines import REFERENCES
from scripts.run_scientific_validation import TARGET, frozen_snapshot


def isolated_smoke(document, snapshot, image, context):
    with tempfile.TemporaryDirectory(prefix="sbom-repair-") as directory:
        work = Path(directory)
        inputs, outputs = work / "input", work / "output"
        inputs.mkdir()
        outputs.mkdir()
        sources = ("repair_agent.py", "graph_triage.py", "research_core.py", "resolver.py", "registry_provider.py")
        for name in sources:
            shutil.copyfile(ROOT / name, inputs / name)
        shutil.copyfile(ROOT / "scripts/repair_agent_worker.py", inputs / "repair_agent_worker.py")
        schema_dir = inputs / "research/schemas"
        schema_dir.mkdir(parents=True)
        for path in (ROOT / "research/schemas").glob("*.schema.json"):
            shutil.copyfile(path, schema_dir / path.name)
        frozen_snapshot(Path(snapshot), inputs / "evidence_snapshot")
        save(inputs / "input.cdx.json", document)
        save(inputs / "context.json", context)
        command = ["docker", "run", "--rm", "--network", "none", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
                   "--read-only", "--memory=1g", "--cpus=1", "--pids-limit=64", "--user", "1000:1000",
                   "-e", "PYTHONDONTWRITEBYTECODE=1", "-v", f"{inputs}:/work:ro", "-v", f"{outputs}:/out:rw",
                   "--entrypoint", "python", image, "/work/repair_agent_worker.py", "--input", "/work/input.cdx.json",
                   "--evidence", "/work/evidence_snapshot", "--context", "/work/context.json", "--out", "/out/result.json"]
        started_at, started = now(), time.perf_counter()
        result = run_container(command, timeout=90)
        trace = {"command": command, "started_at": started_at, "completed_at": now(),
                 "duration_seconds": time.perf_counter() - started, "exit_code": result.returncode,
                 "network": "none", "oracle_mounted": False, "read_only_root": True,
                 "input_sha256": digest(inputs / "input.cdx.json"), "context_sha256": digest(inputs / "context.json"),
                 "evidence_manifest_sha256": digest(inputs / "evidence_snapshot/evidence_manifest.json"),
                 "code_sha256": {name: digest(inputs / name) for name in (*sources, "repair_agent_worker.py")},
                 "stdout": result.stdout, "stderr": result.stderr}
        if result.returncode:
            return None, trace
        return load(outputs / "result.json"), trace


def run(out, raw, controlled):
    bundle = RunBundle(out, Path(out).name, purpose="Offline scripted tool protocol and verifier smoke; NOT an LLM benchmark",
                       data_kind="EMPIRICAL_INPUTS_WITH_SCRIPTED_POLICY", model_api_calls=0, ml_training=False)
    bundle.data["protocol"] = "m2.4-repair-prototype-v1"
    rows = []
    try:
        for track, source in (("raw", Path(raw)), ("controlled", Path(controlled))):
            image = load(source / "context.json")["image"]
            for path in sorted(source.glob("*/syft/normalized.cdx.json")):
                project = path.parent.parent.name
                document = load(path)
                scope = load(path.parent / "scope.json")
                for regime in ("partial", "sdist"):
                    snapshot = source / "evidence_snapshot" / regime
                    context = {**TARGET, "python_full_version": load(source / "context.json")["python_full_version"]}
                    result, trace = isolated_smoke(document, snapshot, image, context)
                    prefix = f"{track}/{project}/{regime}"
                    bundle.artifact(prefix + "/container_trace.json", trace)
                    if result is None:
                        raise RuntimeError("Prototype container failed; inspect " + prefix + "/container_trace.json")
                    result["verified"]["candidate_document"] = reconstructed_document(result["verified"]["candidate_document"])
                    candidate = result["verified"]["candidate_document"]
                    validation = validate_cdx(candidate)
                    bundle.artifact(prefix + "/result.json", result)
                    bundle.artifact(prefix + "/reconstructed.cdx.json", candidate)
                    bundle.artifact(prefix + "/schema_validation.json", validation)
                    # Evaluation labels never enter the container or the proposal policy.
                    gold_path = ROOT / REFERENCES[project]
                    gold = load(gold_path)
                    _, observed = graph(document)
                    _, predicted = graph(candidate)
                    evaluation = score_application(gold, observed, predicted, scope)
                    b3_score = score_application(gold, observed, set(map(tuple, result["b3_predicted_edges"])), scope)
                    bundle.artifact(prefix + "/evaluation.json", evaluation)
                    rows.append({"track": track, "project": project, "regime": regime, "result_file": prefix + "/result.json",
                        "oracle_source": REFERENCES[project], "oracle_sha256": digest(gold_path),
                        "input_source": str(path.relative_to(ROOT)), "input_sha256": digest(path),
                        "evidence_source": str(snapshot.relative_to(ROOT)), "context": context,
                        "accepted_proposals": len(result["verified"]["accepted"]), "rejected_proposals": len(result["verified"]["rejected"]),
                        "tool_calls": result["tool_calls"], "container_seconds": trace["duration_seconds"],
                        "whole_graph": evaluation["whole_graph"], "additions": evaluation["additions"],
                        "b3_whole_graph": b3_score["whole_graph"], "edges_equal_to_b3": predicted == set(map(tuple, result["b3_predicted_edges"])),
                        "false_positive_edges": evaluation["false_positive_edges"], "missed_edges": evaluation["missed_edges"]})
        bundle.artifact("agent_results.json", {"status": "SCRIPTED_PROTOCOL_SMOKE_EXECUTED", "records": rows,
            "allowed_tools": ["inspect_graph", "metadata", "resolve", "validate"], "max_tool_calls_per_session": 64,
            "model_api_calls": 0, "tokens": None, "model_cost": None, "llm_only": "NOT_RUN_NO_API_CREDENTIAL",
            "tool_using_llm": "NOT_RUN_NO_API_CREDENTIAL", "llm_plus_verifier": "NOT_RUN_NO_API_CREDENTIAL",
            "reproducibility": "Frozen inputs/evidence/code/image and deterministic policy; timestamps and durations vary",
            "interpretation": "Protocol smoke on real inputs only; policy delegates to B3. No learned-method quality or superiority claim.",
            "downstream_metrics": "UNMEASURED"})
        bundle.finish()
        print({"scripted_sessions": len(rows), "model_api_calls": 0, "out": str(out)})
    except Exception as exc:
        bundle.finish("FAILED", error=str(exc))
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--raw", type=Path, default=ROOT / "runs/m23-validation-v2")
    parser.add_argument("--controlled", type=Path, default=ROOT / "runs/m23-controlled-repair-v2")
    args = parser.parse_args()
    run(args.out, args.raw, args.controlled)
