#!/usr/bin/env python3
"""Pilot M2.2 Execution Script: End-to-End Blind Reconstruction on Clean Installation.

Performs:
1. Loads clean containerized ground truth from runs/pilot-container-requests/
2. Synthesizes degraded observed SBOM (simulating generator omission: missing transitive edges)
3. Executes Blind Reconstruction via ContextAwareResolver using FrozenRegistryEvidenceProvider (strictly isolated)
4. Computes standardized evaluation metrics for both:
   - Regime K (Known Context: Linux x86_64 Python 3.11, extras=[])
   - Regime U (Unknown Context: MUST, MAY, UNKNOWN epistemic modalities)
5. Generates comprehensive audit report for Research Lead.
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from registry_provider import FrozenRegistryEvidenceProvider
from resolver import ContextAwareResolver, TargetEnvironment, PLAUSIBLE_ENVIRONMENTS, normalize_purl
from evaluator import (
    evaluate_reconstruction_edges,
    evaluate_reconstruction_nodes,
    evaluate_regime_u_uncertainty,
    evaluate_security_vrr
)


def run_m2_pilot():
    runs_dir = ROOT / "runs" / "pilot-container-requests"
    gt_cdx_file = runs_dir / "ground_truth.cdx.json"
    gt_graph_file = runs_dir / "ground_truth.json"

    if not gt_cdx_file.exists():
        raise FileNotFoundError(f"Container ground truth not found at {gt_cdx_file}")

    gt_cdx = json.loads(gt_cdx_file.read_text(encoding="utf-8"))
    gt_data = json.loads(gt_graph_file.read_text(encoding="utf-8"))

    print(f"[*] Loaded containerized ground truth: {gt_data['project']}")
    print(f"    - Packages: {gt_data['counts']['packages']}")
    print(f"    - Direct package edges: {gt_data['counts']['direct_package_edges']}")

    # Ground truth edges in canonical (source_purl, target_purl) format
    purl_by_name = {n["name"]: n["purl"] for n in gt_data["nodes"]}
    E_t = {
        (normalize_purl(purl_by_name[e["from"]]), normalize_purl(purl_by_name[e["to"]]))
        for e in gt_data["edges"]
    }

    # Simulate observed degraded SBOM (Generator Omission: flat SBOM without dependency edges)
    # This matches common generator discrepancies (e.g. Syft flat package list)
    degraded_sbom = {
        "bomFormat": gt_cdx["bomFormat"],
        "specVersion": gt_cdx["specVersion"],
        "metadata": gt_cdx["metadata"],
        "components": gt_cdx.get("components", []),
        "dependencies": [
            {"ref": c.get("bom-ref"), "dependsOn": []}
            for c in [gt_cdx["metadata"]["component"]] + gt_cdx.get("components", [])
            if c.get("bom-ref")
        ]
    }
    E_o = set()  # Observed edges = 0 (completely omitted by generator)

    # Instantiate Frozen Evidence Provider (strict isolation barrier)
    snapshot_dir = ROOT / "fixtures" / "evidence_snapshot"
    provider = FrozenRegistryEvidenceProvider(snapshot_dir)
    resolver = ContextAwareResolver(provider)

    # -------------------------------------------------------------
    # REGIME K: Known Context Evaluation
    # -------------------------------------------------------------
    env_k = TargetEnvironment(
        os_name="posix",
        sys_platform="linux",
        platform_machine="x86_64",
        python_version="3.11",
        platform_system="Linux",
        active_extras=set()
    )

    resolved_k = resolver.resolve(degraded_sbom, target_env=env_k)
    reconstructed_cdx_k = resolved_k["G_reconstructed"]

    # Extract predicted edges from reconstructed SBOM
    comp_by_ref = {c.get("bom-ref"): normalize_purl(c.get("purl")) for c in [reconstructed_cdx_k["metadata"]["component"]] + reconstructed_cdx_k.get("components", [])}
    E_p_k = set()
    for d in reconstructed_cdx_k.get("dependencies", []):
        src_purl = comp_by_ref.get(d.get("ref"))
        for target_ref in d.get("dependsOn", []):
            tgt_purl = comp_by_ref.get(target_ref)
            if src_purl and tgt_purl:
                E_p_k.add((src_purl, tgt_purl))

    edge_eval_k = evaluate_reconstruction_edges(E_t, E_o, E_p_k)

    # -------------------------------------------------------------
    # REGIME U: Unknown/Partial Context Evaluation
    # -------------------------------------------------------------
    resolved_u = resolver.resolve(degraded_sbom, target_env=None, candidate_environments=PLAUSIBLE_ENVIRONMENTS)
    candidate_edges_u = resolved_u["G_candidate"]["edges"]

    # Target ground truth edges mapped by env id
    gt_by_env = {
        "linux_3.11": E_t,
        "linux_3.10": E_t,
        "linux_3.12": E_t,
        "win32_3.11": E_t,
        "darwin_3.11": E_t
    }
    eval_u = evaluate_regime_u_uncertainty(candidate_edges_u, gt_by_env, target_env_id="linux_3.11")

    # Security Evaluation (simulated advisory reachability on urllib3)
    # In requests 2.31.0, urllib3 is a direct dependency.
    # Suppose urllib3 has a known advisory in target environment:
    vulnerable_nodes = {normalize_purl(purl_by_name["urllib3"])}
    reachable_obs = set() # unlinked in degraded
    reachable_pred_k = {tgt for src, tgt in E_p_k if "requests" in src}
    sec_eval = evaluate_security_vrr(vulnerable_nodes, reachable_obs, reachable_pred_k)

    results = {
        "project": gt_data["project"],
        "experiment": "M2.2 Blind Real-World Pilot Reconstruction",
        "ground_truth_counts": gt_data["counts"],
        "regime_k": edge_eval_k,
        "regime_u": eval_u,
        "security_vrr": sec_eval,
        "contradictions_detected": len(resolved_k["G_candidate"]["contradictions"])
    }

    out_file = ROOT / "runs" / "pilot_m2_reconstruction.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"[OK] M2.2 pilot evaluation results saved to {out_file}")
    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    run_m2_pilot()
