#!/usr/bin/env python3
"""Standardized Evaluation Protocol for SBOM Graph Reconstruction.

Strictly adheres to Research Lead's formal specification:
1. Evaluates ONLY newly recovered edges/components (prevents observed edges from inflating F1).
2. Computes Regime K (Known Context) metrics: P, R, F1 on E_new vs E_m.
3. Computes Regime U (Unknown Context) metrics: MUST Precision, MAY Recall, False-Certainty Rate, Abstention Rate, Coverage.
4. Downstream Vulnerability Recovery Rate (VRR) & Triage Delta.
"""
from typing import Dict, List, Optional, Set, Tuple, Any


def evaluate_reconstruction_edges(
    ground_truth_edges: Set[Tuple[str, str]],
    observed_edges: Set[Tuple[str, str]],
    predicted_edges: Set[Tuple[str, str]],
) -> Dict[str, Any]:
    """
    E_t: ground_truth_edges
    E_o: observed_edges
    E_p: predicted_edges
    E_m = E_t - E_o (actually missing edges)
    E_new = E_p - E_o (newly proposed edges)
    """
    E_t = ground_truth_edges
    E_o = observed_edges
    E_p = predicted_edges

    E_m = E_t - E_o
    E_new = E_p - E_o

    tp = len(E_new & E_m)
    fp = len(E_new - E_t)
    fn = len(E_m - E_new)

    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if len(E_m) == 0 else 0.0)
    f1 = (2 * tp) / (2 * tp + fp + fn) if (2 * tp + fp + fn) > 0 else (1.0 if len(E_m) == 0 and len(E_new) == 0 else 0.0)

    return {
        "ground_truth_total": len(E_t),
        "observed_total": len(E_o),
        "actually_missing_total": len(E_m),
        "newly_proposed_total": len(E_new),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "recovered_edges": sorted(list(E_new & E_m)),
        "false_positive_edges": sorted(list(E_new - E_t)),
        "missed_edges": sorted(list(E_m - E_new)),
    }


def evaluate_reconstruction_nodes(
    ground_truth_nodes: Set[str],
    observed_nodes: Set[str],
    predicted_nodes: Set[str],
) -> Dict[str, Any]:
    C_t = ground_truth_nodes
    C_o = observed_nodes
    C_p = predicted_nodes

    C_m = C_t - C_o
    C_new = C_p - C_o

    tp = len(C_new & C_m)
    fp = len(C_new - C_t)
    fn = len(C_m - C_new)

    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if len(C_m) == 0 else 0.0)
    f1 = (2 * tp) / (2 * tp + fp + fn) if (2 * tp + fp + fn) > 0 else (1.0 if len(C_m) == 0 and len(C_new) == 0 else 0.0)

    return {
        "ground_truth_components": len(C_t),
        "observed_components": len(C_o),
        "actually_missing_components": len(C_m),
        "newly_proposed_components": len(C_new),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "recovered_components": sorted(list(C_new & C_m)),
        "false_positive_components": sorted(list(C_new - C_t)),
        "missed_components": sorted(list(C_m - C_new)),
    }


def evaluate_regime_u_uncertainty(
    candidate_edges: List[Dict[str, Any]],
    ground_truth_edges_by_env: Dict[str, Set[Tuple[str, str]]],
    target_env_id: str
) -> Dict[str, Any]:
    """
    Evaluates Regime U (Unspecified/Partial Environment Context):
    Strictly adheres to Research Lead's formal semantics:
    - MUST: Edge is present across ALL plausible environments in E_plausible.
    - MAY_ONLY: Edge is present in SOME plausible environments, but not all.
    - POSSIBLE: MUST union MAY_ONLY.
    - UNKNOWN / ABSTAIN: Insufficient evidence.
    Invariants enforced: MUST intersect MAY_ONLY == empty, MUST subset of POSSIBLE.
    """
    target_edges = ground_truth_edges_by_env.get(target_env_id, set())

    # Union of all environments
    all_env_edges = set().union(*ground_truth_edges_by_env.values()) if ground_truth_edges_by_env else set()
    # Intersection of all environments (edges invariant across all plausible envs)
    must_truth = set.intersection(*ground_truth_edges_by_env.values()) if ground_truth_edges_by_env else set()

    predicted_must = {
        (e["source_purl"], e["target_purl"]) for e in candidate_edges if e.get("modality") == "MUST"
    }
    predicted_may_only = {
        (e["source_purl"], e["target_purl"]) for e in candidate_edges if e.get("modality") in ("MAY_ONLY", "MAY")
    }
    unknown_count = sum(1 for e in candidate_edges if e.get("modality") in ("UNKNOWN", "AMBIGUOUS_MATCH"))

    # Enforce mathematical invariants
    assert len(predicted_must & predicted_may_only) == 0, (
        f"Scientific Invariant Violation: MUST and MAY_ONLY must be disjoint! Overlap: {predicted_must & predicted_may_only}"
    )
    predicted_possible = predicted_must | predicted_may_only
    assert predicted_must <= predicted_possible, "Scientific Invariant Violation: MUST must be subset of POSSIBLE!"

    # MUST Precision: What fraction of asserted MUST edges are truly invariant across all plausible environments?
    must_tp = len(predicted_must & must_truth)
    must_precision = must_tp / len(predicted_must) if len(predicted_must) > 0 else None

    # POSSIBLE Recall: What fraction of possible edges across all environments were captured in the POSSIBLE set?
    possible_recall = len(predicted_possible & all_env_edges) / len(all_env_edges) if len(all_env_edges) > 0 else 1.0

    # False Certainty Rate: Fraction of predicted MUST edges that are actually conditional (only present in some environments)
    falsely_certain = predicted_must - must_truth
    false_certainty_rate = len(falsely_certain) / len(predicted_must) if len(predicted_must) > 0 else 0.0

    # Abstention Rate: Fraction of candidates abstained / marked UNKNOWN / AMBIGUOUS_MATCH
    total_candidates = len(candidate_edges)
    abstention_rate = unknown_count / total_candidates if total_candidates > 0 else 0.0

    # Coverage on Target Environment: How many of the target environment's true edges were captured by POSSIBLE?
    target_coverage = len(predicted_possible & target_edges) / len(target_edges) if len(target_edges) > 0 else 1.0

    return {
        "regime": "Regime_U_Partial_or_Missing_Context",
        "predicted_must_count": len(predicted_must),
        "predicted_may_only_count": len(predicted_may_only),
        "predicted_possible_count": len(predicted_possible),
        "unknown_count": unknown_count,
        "must_precision": must_precision,
        "possible_recall": possible_recall,
        "false_certainty_rate": false_certainty_rate,
        "abstention_rate": abstention_rate,
        "target_coverage": target_coverage,
        "invariants_verified": {
            "must_intersect_may_only_empty": True,
            "must_subset_possible": True
        },
        "details": {
            "falsely_certain_edges": sorted(list(falsely_certain)),
        }
    }


def evaluate_security_vrr(
    vulnerable_packages_truth: Set[str],
    reachable_observed: Set[str],
    reachable_predicted: Set[str],
    scenario_type: str = "SIMULATED_SECURITY_SCENARIO",
    advisory_id: Optional[str] = None
) -> Dict[str, Any]:
    """Computes Vulnerability Recovery Rate (VRR) and Triage Delta.
    
    Reflects Fail-Closed and Rice's Theorem constraints:
    - Path missing != Safe (reports PATH_NOT_ESTABLISHED_IN_GRAPH, never PROVEN_UNREACHABLE).
    - Clearly demarcates SIMULATED_SECURITY_SCENARIO vs VERIFIED_REAL_ADVISORY.
    - Level 1 Reachability only (Dependency graph path), not Call-Graph (Level 2) or Dynamic Exploitability (Level 3).
    """
    valid_scenarios = ("SIMULATED_SECURITY_SCENARIO", "VERIFIED_REAL_ADVISORY")
    if scenario_type not in valid_scenarios:
        raise ValueError(f"scenario_type must be one of {valid_scenarios}, got: {scenario_type}")

    if not vulnerable_packages_truth:
        return {
            "scenario_type": scenario_type,
            "advisory_id": advisory_id,
            "reachability_level": "Level_1_Dependency_Graph_Path",
            "vrr_observed": "N/A (no ground truth vulnerabilities)",
            "vrr_predicted": "N/A",
            "delta_vrr": "N/A",
            "recovered_vulnerabilities": [],
            "false_positive_vulnerabilities": list(reachable_predicted - vulnerable_packages_truth)
        }

    total_vuln = len(vulnerable_packages_truth)
    found_obs = len(vulnerable_packages_truth & reachable_observed)
    found_pred = len(vulnerable_packages_truth & reachable_predicted)

    vrr_obs = found_obs / total_vuln
    vrr_pred = found_pred / total_vuln
    delta_vrr = vrr_pred - vrr_obs

    unreached_pred = vulnerable_packages_truth - reachable_predicted

    return {
        "scenario_type": scenario_type,
        "advisory_id": advisory_id,
        "reachability_level": "Level_1_Dependency_Graph_Path",
        "scientific_disclaimer": "Level 1 path existence does NOT prove runtime exploitability (Rice's Theorem). Absence of path is PATH_NOT_ESTABLISHED_IN_GRAPH, never PROVEN_SAFE.",
        "ground_truth_vulnerabilities": total_vuln,
        "vrr_observed": vrr_obs,
        "vrr_predicted": vrr_pred,
        "delta_vrr": delta_vrr,
        "recovered_vulnerabilities": sorted(list((vulnerable_packages_truth & reachable_predicted) - reachable_observed)),
        "unestablished_path_vulnerabilities": sorted(list(unreached_pred)),
        "false_positive_vulnerabilities": sorted(list(reachable_predicted - vulnerable_packages_truth))
    }
