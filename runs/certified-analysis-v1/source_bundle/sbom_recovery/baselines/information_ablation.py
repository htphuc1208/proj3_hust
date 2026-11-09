"""Ablate information, not PEP 508 syntax. MUST is relative to enumerated contexts."""
from dataclasses import replace
from itertools import combinations

from sbom_recovery.core.resolver import PLAUSIBLE_ENVIRONMENTS, run_baseline_b3_context_aware


def context_ablation(document, provider, target_env, declared_extras):
    extras = sorted(declared_extras)
    if len(extras) > 8:
        raise ValueError("Extra-subset budget exceeded; do not silently claim complete context enumeration")
    subsets = [set(c) for n in range(len(extras) + 1) for c in combinations(extras, n)]
    results = {}
    for environment_known in (False, True):
        for extras_known in (False, True):
            environments = [target_env] if environment_known else PLAUSIBLE_ENVIRONMENTS
            requested = [target_env.active_extras] if extras_known else subsets
            predicted, unknown, contexts = [], set(), []
            for env in environments:
                for active in requested:
                    context = replace(env, active_extras=set(active))
                    result = run_baseline_b3_context_aware(document, provider, target_env=context)
                    edges = {(e["source_purl"], e["target_purl"]) for e in result["G_candidate"]["edges"]
                             if e["modality"] != "UNKNOWN" and e["status"] != "AMBIGUOUS_MATCH"}
                    unknown.update((e["source_purl"], e["target_purl"]) for e in result["G_candidate"]["edges"]
                                   if e["modality"] == "UNKNOWN")
                    predicted.append(edges)
                    contexts.append({"platform": context.sys_platform, "python": context.python_version,
                                     "requested_extras": sorted(active)})
            must = set.intersection(*predicted) if predicted else set()
            possible = set.union(*predicted) if predicted else set()
            key = f"E{int(environment_known)}X{int(extras_known)}"
            results[key] = {"environment_known": environment_known, "requested_extras_known": extras_known,
                            "contexts": contexts, "must": sorted(must), "may_only": sorted(possible - must),
                            "possible": sorted(possible), "unknown": sorted(unknown),
                            "modality_scope": "Declared finite context set only; no calibrated probabilities",
                            "context_uncertain": not (environment_known and extras_known)}
    return results
