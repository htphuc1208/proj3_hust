#!/usr/bin/env python3
"""Run two real installations and controlled information ablations; no truth-seeded evidence."""
import argparse
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research_core import (RunBundle, digest, graph, load, normalize_sbom, now, save, score_application)
from research_execution import capture_installation
from public_evidence import acquire, expand_snapshot
from registry_provider import FrozenRegistryEvidenceProvider
from resolver import TargetEnvironment
from information_ablation import context_ablation
from scripts.run_scientific_validation import isolated_inference


def run(out, base, replay=None):
    out = Path(out).resolve()
    bundle = RunBundle(out, out.name, purpose="Information ablation; no nominal independent causal effects claim")
    context = load(ROOT / "research/target_context.json")
    inputs, capture_records = [], []
    try:
        for name, specification in [("base", "requests==2.31.0"), ("socks", "requests[socks]==2.31.0")]:
            capture_path = Path(replay).resolve() / name if replay else ROOT / "research/.work" / out.name / name
            capture = load(capture_path / "capture_manifest.json") if replay else capture_installation([specification], capture_path, context["image"])
            for file in capture_path.glob("*.json"):
                bundle.copy(f"{name}/{file.name}", file)
            for file in capture_path.glob("*.log"):
                bundle.copy(f"{name}/{file.name}", file)
            if capture["status"] != "COMPLETE":
                raise RuntimeError(f"Installation {name} blocked; inspect capture_manifest.json")
            document, scope = normalize_sbom(load(capture_path / "original.cdx.json"), "requests", bootstrap=("pip", "setuptools"))
            # Controlled source masking is needed to measure information contribution,
            # otherwise the generator has already supplied the relevant edge.
            document.pop("dependencies", None)
            bundle.artifact(f"{name}/masked_input.cdx.json", document)
            bundle.artifact(f"{name}/scope.json", scope)
            inputs.append(document)
            capture_records.append((name, capture_path, capture, document, scope))
        context.update(cutoff=now(), cutoff_status="OBSERVED_CURRENT_ACQUISITION; contemporary controlled captures")
        snapshot = out / "evidence_snapshot"
        if replay:
            from scripts.run_scientific_validation import frozen_snapshot
            frozen_snapshot(Path(replay) / "evidence_snapshot", snapshot)
        else:
            expand_snapshot(base, snapshot, inputs, context)
        # Provides-Extra is needed to define the hidden-root-extra context domain.
        root_record = load(snapshot / "requests-2.31.0.json") if replay else acquire("requests", "2.31.0", ROOT / "research/.work" / out.name / "public_cache", context)
        manifest = load(snapshot / "evidence_manifest.json")
        entry = next(a for a in manifest["artifacts"] if a["name"] == "requests" and a["version"] == "2.31.0")
        save(snapshot / entry["metadata_file"], root_record)
        entry["sha256"] = digest(snapshot / entry["metadata_file"])
        save(snapshot / "evidence_manifest.json", manifest)
        provider = FrozenRegistryEvidenceProvider(snapshot)
        results = {}
        for name, capture_path, capture, document, scope in capture_records:
            environment = capture["environment"]
            target = TargetEnvironment(**{k: environment[k] for k in ("os_name", "sys_platform", "platform_machine", "python_version", "platform_system", "python_full_version")},
                                       active_extras={"socks"} if name == "socks" else set())
            declared_context = {**target.__dict__, "declared_extras": root_record["provides_extra"]}
            results[name], trace = isolated_inference(document, snapshot, context["image"], declared_context, mode="ablation")
            bundle.artifact(f"{name}/inference_trace.json", trace)
            gold = load(capture_path / "ground_truth.json")
            for arm, result in results[name].items():
                result["must_score"] = score_application(gold, set(), {tuple(e) for e in result["must"]}, scope)["whole_graph"]
                result["possible_score"] = score_application(gold, set(), {tuple(e) for e in result["possible"]}, scope)["whole_graph"]
        bundle.artifact("information_ablation_results.json", {"protocol": "m2.3-information-ablation-v1", "data_kind": "CONTROLLED_SOURCE_MASKING_ON_REAL_INSTALLATIONS",
            "provided_extras_domain": root_record["provides_extra"], "snapshot_sha256": digest(snapshot / "evidence_manifest.json"),
            "results": results, "claim_limit": "Information sensitivity over finite contexts; no independent causal-effects or calibration claim"})
        bundle.finish()
        print(out)
    except Exception as exc:
        bundle.finish("BLOCKED", technical_cause=str(exc))
        raise


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--base-snapshot", type=Path, required=True)
    p.add_argument("--replay", type=Path, help="Reuse frozen installed captures and evidence; no public queries")
    a = p.parse_args()
    run(a.out, a.base_snapshot, a.replay)
