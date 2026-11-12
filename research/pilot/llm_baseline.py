#!/usr/bin/env python3
"""LLM baseline implementations for pilot comparison.

Implements B3 (llm-fixed), B4 (llm-agent), B5 (llm-explainer) baselines
using the investigation framework with controlled comparisons.
"""
import json
from pathlib import Path
from typing import Dict, Any, List

from sbom_recovery.investigation.models import Budget, Action
from sbom_recovery.investigation.planner import GatewayPlanner, ReplayPlanner
from sbom_recovery.investigation.runner import run_investigation


def create_llm_fixed_policy() -> Dict[str, Any]:
    """B3: LLM with full evidence but no tool calls.

    Provides all evidence upfront in initial view, LLM reasons over it
    but cannot acquire additional evidence adaptively.
    """
    return {
        "policy": "fixed_llm",
        "description": "LLM reasoning with pre-loaded evidence, no adaptive acquisition",
        "budget": Budget(
            max_tool_calls=0,  # No evidence acquisition
            max_model_calls=5,
            max_tokens=32768,
            max_cost_usd=0.30,
            max_seconds=60.0,
            input_usd_per_million=3.0,   # GPT-4o pricing
            output_usd_per_million=15.0
        ).model_dump()
    }


def create_llm_agent_policy() -> Dict[str, Any]:
    """B4: LLM agent with adaptive evidence acquisition.

    Agent decides which evidence sources to inspect and when to finish.
    This is the primary method under evaluation.
    """
    return {
        "policy": "agent",
        "description": "Adaptive LLM agent with evidence acquisition budget",
        "budget": Budget(
            max_tool_calls=5,
            max_model_calls=10,
            max_tokens=32768,
            max_cost_usd=0.50,
            max_seconds=120.0,
            input_usd_per_million=3.0,
            output_usd_per_million=15.0
        ).model_dump()
    }


def create_llm_explainer_policy() -> Dict[str, Any]:
    """B5: LLM provides explanations but doesn't make decisions.

    Tests whether LLM value comes from decision-making or explanation quality.
    Decisions still made by deterministic validator.
    """
    return {
        "policy": "agent",
        "description": "LLM explains evidence but validator makes decisions",
        "explain_only": True,
        "budget": Budget(
            max_tool_calls=5,
            max_model_calls=10,
            max_tokens=32768,
            max_cost_usd=0.50,
            max_seconds=120.0,
            input_usd_per_million=3.0,
            output_usd_per_million=15.0
        ).model_dump()
    }


def compare_llm_baselines(
    request_path: Path,
    oracle_path: Path,
    snapshot_path: Path,
    output_dir: Path,
    models: List[str] = None
) -> Dict[str, Any]:
    """Run all LLM baselines on a single case for comparison.

    Args:
        request_path: ReconciliationRequestV3 JSON
        oracle_path: Ground truth oracle JSON
        snapshot_path: Frozen advisory snapshot
        output_dir: Where to write results
        models: List of model identifiers to test (default: GPT-4o, Claude Opus 5.5)

    Returns:
        Comparison results with metrics for each baseline
    """
    if models is None:
        models = [
            "gpt-4o-2024-11-20",
            "claude-opus-5-5",
            "qwen-2.5-72b"
        ]

    results = {
        "case_id": request_path.stem,
        "models_evaluated": models,
        "baselines": {}
    }

    for baseline_name, policy_fn in [
        ("B3_llm_fixed", create_llm_fixed_policy),
        ("B4_llm_agent", create_llm_agent_policy),
        ("B5_llm_explainer", create_llm_explainer_policy)
    ]:
        results["baselines"][baseline_name] = {}

        for model in models:
            print(f"\nRunning {baseline_name} with {model}...")

            policy = policy_fn()
            run_output = output_dir / baseline_name / model / request_path.stem
            run_output.mkdir(parents=True, exist_ok=True)

            try:
                # This would call the actual investigation runner
                # For now, this is a design template
                result = {
                    "model": model,
                    "policy": policy["policy"],
                    "status": "PLACEHOLDER",
                    "metrics": {
                        "component_f1": None,
                        "edge_f1": None,
                        "vulnerability_f1": None,
                        "tool_calls_used": None,
                        "tokens_used": None,
                        "cost_usd": None,
                        "wall_clock_seconds": None
                    }
                }

                results["baselines"][baseline_name][model] = result

            except Exception as e:
                print(f"  Error: {e}")
                results["baselines"][baseline_name][model] = {
                    "error": str(e),
                    "status": "FAILED"
                }

    return results


def analyze_llm_comparison(results: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze differences between LLM baselines.

    Key questions:
    1. Does adaptive acquisition (B4) outperform fixed evidence (B3)?
    2. Does LLM decision-making (B4) outperform explanation-only (B5)?
    3. Which model performs best at evidence acquisition?
    4. What is the accuracy vs cost trade-off?
    """
    analysis = {
        "summary": {},
        "pairwise_comparisons": {},
        "model_rankings": {},
        "efficiency_analysis": {}
    }

    # Extract metrics from results
    baselines = results.get("baselines", {})

    # Compare B3 vs B4: Does adaptive acquisition help?
    if "B3_llm_fixed" in baselines and "B4_llm_agent" in baselines:
        analysis["pairwise_comparisons"]["B3_vs_B4"] = {
            "question": "Does adaptive acquisition improve over fixed evidence?",
            "metrics": ["component_f1", "edge_f1", "vulnerability_f1"],
            "winner": "PENDING_EVALUATION"
        }

    # Compare B4 vs B5: Does decision-making help?
    if "B4_llm_agent" in baselines and "B5_llm_explainer" in baselines:
        analysis["pairwise_comparisons"]["B4_vs_B5"] = {
            "question": "Does LLM decision-making outperform explanation-only?",
            "metrics": ["component_f1", "edge_f1", "incorrect_correction_rate"],
            "winner": "PENDING_EVALUATION"
        }

    # Model comparison
    for baseline_name in baselines:
        analysis["model_rankings"][baseline_name] = {
            "by_accuracy": [],
            "by_efficiency": [],
            "by_cost": []
        }

    return analysis


def main():
    """Example: Compare LLM baselines on controlled case."""
    pilot_dir = Path(__file__).parent
    examples_dir = Path(__file__).parent.parent.parent / "examples" / "investigation-v3"

    # Use existing controlled npm example
    request = examples_dir / "npm" / "request.json"
    oracle = examples_dir / "npm" / "oracle" / "oracle.json"
    snapshot = examples_dir / "npm" / "advisories.json"
    output = pilot_dir / "llm_comparison_output"

    if not request.exists():
        print(f"Error: Example request not found at {request}")
        print("Run: .venv/bin/python -m sbom_recovery investigation demo")
        return

    print("EAGER-SBOM LLM Baseline Comparison")
    print("=" * 50)
    print(f"Request: {request}")
    print(f"Oracle: {oracle}")
    print(f"Output: {output}")

    results = compare_llm_baselines(request, oracle, snapshot, output)

    # Write results
    results_file = output / "llm_comparison.json"
    results_file.parent.mkdir(parents=True, exist_ok=True)
    results_file.write_text(json.dumps(results, indent=2))

    # Analyze
    analysis = analyze_llm_comparison(results)
    analysis_file = output / "llm_analysis.json"
    analysis_file.write_text(json.dumps(analysis, indent=2))

    print(f"\nResults: {results_file}")
    print(f"Analysis: {analysis_file}")


if __name__ == "__main__":
    main()
