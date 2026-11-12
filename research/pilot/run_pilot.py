#!/usr/bin/env python3
"""Run EAGER-SBOM pilot benchmark evaluation.

Compares deterministic baselines (B0-B2) with LLM-assisted methods (B3-B5)
on controlled cases to evaluate adaptive evidence acquisition.
"""
import json
import sys
from pathlib import Path
from typing import Dict, Any, List
import time

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sbom_recovery.investigation.cli import run_investigation_command, score_prediction
from sbom_recovery.investigation.models import Budget


class PilotRunner:
    """Orchestrate pilot benchmark evaluation."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = {
            "pilot_version": "v1",
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "cases": []
        }

    def run_case(
        self,
        case_id: str,
        request_path: Path,
        oracle_path: Path,
        snapshot_path: Path
    ) -> Dict[str, Any]:
        """Run all baselines on a single case."""
        print(f"\n{'='*60}")
        print(f"Case: {case_id}")
        print(f"{'='*60}")

        case_output = self.output_dir / case_id
        case_output.mkdir(exist_ok=True)

        case_results = {
            "case_id": case_id,
            "request": str(request_path),
            "oracle": str(oracle_path),
            "baselines": {}
        }

        # B0: sbom-unifier baseline
        print("\n[B0] sbom-unifier...")
        b0_result = self._run_baseline(
            "B0_sbom_unifier",
            request_path,
            oracle_path,
            snapshot_path,
            case_output,
            policy="observed",
            description="Original sbom-unifier merge behavior"
        )
        case_results["baselines"]["B0_sbom_unifier"] = b0_result

        # B1: Deterministic with full evidence
        print("\n[B1] Deterministic (full evidence)...")
        b1_result = self._run_baseline(
            "B1_deterministic",
            request_path,
            oracle_path,
            snapshot_path,
            case_output,
            policy="deterministic",
            description="Fixed priority with all evidence"
        )
        case_results["baselines"]["B1_deterministic"] = b1_result

        # B2: Rule-based heuristic
        print("\n[B2] Rule-based heuristic...")
        b2_result = self._run_baseline(
            "B2_rule",
            request_path,
            oracle_path,
            snapshot_path,
            case_output,
            policy="rule",
            budget=Budget(max_tool_calls=5, max_steps=20),
            description="Heuristic evidence ranking with budget"
        )
        case_results["baselines"]["B2_rule"] = b2_result

        # B3: LLM with fixed evidence (no tool calls)
        print("\n[B3] LLM fixed evidence...")
        b3_result = self._run_llm_baseline(
            "B3_llm_fixed",
            request_path,
            oracle_path,
            snapshot_path,
            case_output,
            policy="fixed_llm",
            budget=Budget(
                max_tool_calls=0,
                max_model_calls=5,
                max_tokens=32768,
                max_cost_usd=0.30
            ),
            description="LLM reasoning without adaptive acquisition"
        )
        case_results["baselines"]["B3_llm_fixed"] = b3_result

        # B4: LLM agent with adaptive acquisition
        print("\n[B4] LLM agent (adaptive)...")
        b4_result = self._run_llm_baseline(
            "B4_llm_agent",
            request_path,
            oracle_path,
            snapshot_path,
            case_output,
            policy="agent",
            budget=Budget(
                max_tool_calls=5,
                max_model_calls=10,
                max_tokens=32768,
                max_cost_usd=0.50
            ),
            description="Adaptive LLM agent with evidence acquisition"
        )
        case_results["baselines"]["B4_llm_agent"] = b4_result

        return case_results

    def _run_baseline(
        self,
        baseline_id: str,
        request_path: Path,
        oracle_path: Path,
        snapshot_path: Path,
        case_output: Path,
        policy: str,
        budget: Budget = None,
        description: str = ""
    ) -> Dict[str, Any]:
        """Run a single baseline method."""
        run_output = case_output / baseline_id
        run_output.mkdir(exist_ok=True)

        start_time = time.time()
        status = "SUCCESS"
        error = None

        try:
            # Run investigation
            run_investigation_command(
                request=str(request_path),
                policy=policy,
                out=str(run_output),
                snapshot=str(snapshot_path) if snapshot_path.exists() else None,
                budget=budget.model_dump() if budget else None,
                metadata_only=False,
                graph_only=False
            )

            # Score prediction against oracle
            prediction_path = run_output / "prediction.json"
            score_output = run_output / "scores.json"

            if prediction_path.exists() and oracle_path.exists():
                score_prediction(
                    prediction=str(prediction_path),
                    oracle=str(oracle_path),
                    out=str(score_output)
                )

                # Load scores
                scores = json.loads(score_output.read_text())
            else:
                scores = {"error": "prediction or oracle not found"}
                status = "PARTIAL"

        except Exception as e:
            error = str(e)
            status = "FAILED"
            scores = {}
            print(f"  Error: {error}")

        elapsed = time.time() - start_time

        return {
            "baseline_id": baseline_id,
            "description": description,
            "policy": policy,
            "budget": budget.model_dump() if budget else None,
            "status": status,
            "error": error,
            "elapsed_seconds": elapsed,
            "output_dir": str(run_output),
            "scores": scores
        }

    def _run_llm_baseline(
        self,
        baseline_id: str,
        request_path: Path,
        oracle_path: Path,
        snapshot_path: Path,
        case_output: Path,
        policy: str,
        budget: Budget,
        description: str = ""
    ) -> Dict[str, Any]:
        """Run LLM baseline (B3, B4, or B5)."""
        # Check if LLM is available
        import os
        if not os.environ.get("NETMIND_API_KEY"):
            print(f"  Skipped: NETMIND_API_KEY not set")
            return {
                "baseline_id": baseline_id,
                "description": description,
                "status": "SKIPPED",
                "reason": "NETMIND_API_KEY not configured"
            }

        # For now, use deterministic as placeholder
        # Real implementation would use agent policy with model
        return self._run_baseline(
            baseline_id,
            request_path,
            oracle_path,
            snapshot_path,
            case_output,
            policy="deterministic",  # Placeholder
            budget=budget,
            description=f"{description} (placeholder: needs LLM integration)"
        )

    def run_pilot(self, cases: List[Dict[str, Any]]):
        """Run pilot on all cases."""
        print("EAGER-SBOM Pilot Benchmark")
        print("="*60)
        print(f"Output directory: {self.output_dir}")
        print(f"Cases: {len(cases)}")

        for case in cases:
            case_result = self.run_case(
                case["case_id"],
                Path(case["request"]),
                Path(case["oracle"]),
                Path(case["snapshot"])
            )
            self.results["cases"].append(case_result)

        # Write final results
        self.results["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        results_file = self.output_dir / "pilot_results.json"
        results_file.write_text(json.dumps(self.results, indent=2))

        # Generate summary
        self._generate_summary()

        print(f"\n{'='*60}")
        print(f"Pilot complete: {results_file}")
        print(f"{'='*60}")

    def _generate_summary(self):
        """Generate summary statistics and comparisons."""
        summary = {
            "total_cases": len(self.results["cases"]),
            "baseline_comparison": {},
            "key_findings": []
        }

        # Collect metrics by baseline
        baseline_metrics = {}
        for case in self.results["cases"]:
            for baseline_id, result in case["baselines"].items():
                if baseline_id not in baseline_metrics:
                    baseline_metrics[baseline_id] = {
                        "successes": 0,
                        "failures": 0,
                        "component_f1_sum": 0,
                        "edge_f1_sum": 0,
                        "vuln_f1_sum": 0,
                        "count": 0
                    }

                metrics = baseline_metrics[baseline_id]
                if result["status"] == "SUCCESS":
                    metrics["successes"] += 1
                    scores = result.get("scores", {})
                    metrics["component_f1_sum"] += scores.get("component_f1", 0)
                    metrics["edge_f1_sum"] += scores.get("edge_f1", 0)
                    metrics["vuln_f1_sum"] += scores.get("vulnerability_f1", 0)
                    metrics["count"] += 1
                else:
                    metrics["failures"] += 1

        # Compute averages
        for baseline_id, metrics in baseline_metrics.items():
            count = max(1, metrics["count"])
            summary["baseline_comparison"][baseline_id] = {
                "success_rate": metrics["successes"] / (metrics["successes"] + metrics["failures"]),
                "avg_component_f1": metrics["component_f1_sum"] / count,
                "avg_edge_f1": metrics["edge_f1_sum"] / count,
                "avg_vuln_f1": metrics["vuln_f1_sum"] / count
            }

        # Key findings (placeholder logic)
        b1_f1 = summary["baseline_comparison"].get("B1_deterministic", {}).get("avg_component_f1", 0)
        b2_f1 = summary["baseline_comparison"].get("B2_rule", {}).get("avg_component_f1", 0)
        b4_f1 = summary["baseline_comparison"].get("B4_llm_agent", {}).get("avg_component_f1", 0)

        if b4_f1 > b1_f1:
            summary["key_findings"].append(
                f"B4 (LLM agent) outperforms B1 (deterministic) in component F1: {b4_f1:.3f} vs {b1_f1:.3f}"
            )
        elif b2_f1 > b4_f1:
            summary["key_findings"].append(
                f"B2 (rule-based) outperforms B4 (LLM agent) in component F1: {b2_f1:.3f} vs {b4_f1:.3f}"
            )

        summary_file = self.output_dir / "pilot_summary.json"
        summary_file.write_text(json.dumps(summary, indent=2))

        print("\nPilot Summary:")
        print(json.dumps(summary, indent=2))


def main():
    """Run pilot on controlled examples."""
    # Use existing investigation-v3 examples
    examples_dir = Path(__file__).parent.parent.parent / "examples" / "investigation-v3"
    output_dir = Path(__file__).parent / "pilot_output"

    # Check if examples exist
    if not examples_dir.exists():
        print(f"Error: Examples directory not found: {examples_dir}")
        print("Run: .venv/bin/python -m sbom_recovery investigation demo")
        return 1

    # Define cases
    cases = []

    npm_request = examples_dir / "npm" / "request.json"
    if npm_request.exists():
        cases.append({
            "case_id": "controlled-npm",
            "request": str(npm_request),
            "oracle": str(examples_dir / "npm" / "oracle" / "oracle.json"),
            "snapshot": str(examples_dir / "npm" / "advisories.json")
        })

    cargo_request = examples_dir / "cargo" / "request.json"
    if cargo_request.exists():
        cases.append({
            "case_id": "controlled-cargo",
            "request": str(cargo_request),
            "oracle": str(examples_dir / "cargo" / "oracle" / "oracle.json"),
            "snapshot": str(examples_dir / "cargo" / "advisories.json")
        })

    if not cases:
        print("Error: No controlled cases found")
        print("Run: .venv/bin/python -m sbom_recovery investigation demo")
        return 1

    # Run pilot
    runner = PilotRunner(output_dir)
    runner.run_pilot(cases)

    return 0


if __name__ == "__main__":
    sys.exit(main())
