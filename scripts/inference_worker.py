#!/usr/bin/env python3
"""Offline inference entrypoint. Its container receives no oracle mount."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from resolver import (TargetEnvironment, run_baseline_b0_observed_only, run_baseline_b1_context_free,
                      run_baseline_b2_maximal_supergraph, run_baseline_b3_context_aware)
from registry_provider import FrozenRegistryEvidenceProvider


def infer(document, snapshot, context):
    provider = FrozenRegistryEvidenceProvider(Path(snapshot))
    env = TargetEnvironment(**{**context, "active_extras": set(context.get("active_extras", []))})
    return {"B0": run_baseline_b0_observed_only(document),
            "B1": run_baseline_b1_context_free(document, provider),
            "B2": run_baseline_b2_maximal_supergraph(document, provider),
            "B3": run_baseline_b3_context_aware(document, provider, target_env=env)}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    for name in ("input", "evidence", "context", "out"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--mode", choices=("baseline", "ablation"), default="baseline")
    a = p.parse_args()
    context = json.loads(Path(a.context).read_text())
    if a.mode == "ablation":
        from information_ablation import context_ablation
        extras = context.pop("declared_extras")
        env = TargetEnvironment(**{**context, "active_extras": set(context.get("active_extras", []))})
        result = context_ablation(json.loads(Path(a.input).read_text()), FrozenRegistryEvidenceProvider(Path(a.evidence)), env, extras)
    else:
        result = infer(json.loads(Path(a.input).read_text()), a.evidence, context)
    Path(a.out).write_text(json.dumps(result, indent=2, sort_keys=True,
                                    default=lambda value: sorted(value) if isinstance(value, set) else str(value)) + "\n")
