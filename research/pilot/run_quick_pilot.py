#!/usr/bin/env python3
"""Run EAGER-SBOM pilot with Netmind models."""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sbom_recovery.investigation.cli import main as investigation_main


def run_baseline_comparison():
    """Run B1 (deterministic) and B2 (rule) baselines on demo cases."""
    demo_dir = Path("/tmp/eager-pilot-demo")
    output_dir = Path(__file__).parent / "pilot_output"
    output_dir.mkdir(exist_ok=True)

    cases = [
        ("npm", demo_dir / "npm"),
        ("cargo", demo_dir / "cargo")
    ]

    results = {"cases": []}

    for ecosystem, case_dir in cases:
        request_file = case_dir / "request.json"
        oracle_file = case_dir / "oracle" / "oracle.json"
        snapshot_file = case_dir / "advisories.json"

        if not request_file.exists():
            print(f"Skipping {ecosystem}: request file not found")
            continue

        print(f"\n{'='*60}")
        print(f"Running {ecosystem} case")
        print(f"{'='*60}")

        case_result = {"ecosystem": ecosystem, "baselines": {}}

        # B1: Deterministic baseline
        print("\n[B1] Deterministic baseline...")
        b1_out = output_dir / f"{ecosystem}_B1_deterministic"
        b1_out.mkdir(exist_ok=True)

        sys.argv = [
            "investigation", "run",
            "--request", str(request_file),
            "--policy", "deterministic",
            "--out", str(b1_out),
            "--snapshot", str(snapshot_file)
        ]

        try:
            investigation_main()

            # Score
            sys.argv = [
                "investigation", "score",
                "--prediction", str(b1_out / "prediction.json"),
                "--oracle", str(oracle_file),
                "--out", str(b1_out / "scores.json")
            ]
            investigation_main()

            scores = json.loads((b1_out / "scores.json").read_text())
            case_result["baselines"]["B1_deterministic"] = {
                "status": "SUCCESS",
                "scores": scores
            }
            print(f"  Component F1: {scores.get('component_f1', 'N/A')}")
            print(f"  Edge F1: {scores.get('edge_f1', 'N/A')}")

        except Exception as e:
            print(f"  Error: {e}")
            case_result["baselines"]["B1_deterministic"] = {"status": "FAILED", "error": str(e)}

        # B2: Rule-based baseline
        print("\n[B2] Rule-based baseline...")
        b2_out = output_dir / f"{ecosystem}_B2_rule"
        b2_out.mkdir(exist_ok=True)

        sys.argv = [
            "investigation", "run",
            "--request", str(request_file),
            "--policy", "rule",
            "--out", str(b2_out),
            "--snapshot", str(snapshot_file)
        ]

        try:
            investigation_main()

            # Score
            sys.argv = [
                "investigation", "score",
                "--prediction", str(b2_out / "prediction.json"),
                "--oracle", str(oracle_file),
                "--out", str(b2_out / "scores.json")
            ]
            investigation_main()

            scores = json.loads((b2_out / "scores.json").read_text())
            case_result["baselines"]["B2_rule"] = {
                "status": "SUCCESS",
                "scores": scores
            }
            print(f"  Component F1: {scores.get('component_f1', 'N/A')}")
            print(f"  Edge F1: {scores.get('edge_f1', 'N/A')}")

        except Exception as e:
            print(f"  Error: {e}")
            case_result["baselines"]["B2_rule"] = {"status": "FAILED", "error": str(e)}

        results["cases"].append(case_result)

    # Save results
    results_file = output_dir / "baseline_results.json"
    results_file.write_text(json.dumps(results, indent=2))

    print(f"\n{'='*60}")
    print(f"Results saved to: {results_file}")
    print(f"{'='*60}")

    return results


def run_llm_agent_test():
    """Test LLM agent with Claude Sonnet 5."""
    if not os.environ.get("NETMIND_API_KEY"):
        print("⚠️  NETMIND_API_KEY not set, skipping LLM test")
        return None

    demo_dir = Path("/tmp/eager-pilot-demo")
    output_dir = Path(__file__).parent / "pilot_output"

    npm_request = demo_dir / "npm" / "request.json"
    npm_oracle = demo_dir / "npm" / "oracle" / "oracle.json"
    npm_snapshot = demo_dir / "npm" / "advisories.json"

    if not npm_request.exists():
        print("npm request not found")
        return None

    print(f"\n{'='*60}")
    print("Testing B4: LLM Agent (Claude Sonnet 5)")
    print(f"{'='*60}")

    b4_out = output_dir / "npm_B4_llm_agent"
    b4_out.mkdir(exist_ok=True)

    # Write budget config
    budget_file = b4_out / "budget.json"
    budget_file.write_text(json.dumps({
        "max_tool_calls": 5,
        "max_model_calls": 10,
        "max_tokens": 32768,
        "max_cost_usd": 0.50,
        "max_seconds": 120.0,
        "input_usd_per_million": 3.0,
        "output_usd_per_million": 15.0
    }, indent=2))

    sys.argv = [
        "investigation", "run",
        "--request", str(npm_request),
        "--policy", "agent",
        "--model", "claude-sonnet-5",
        "--budget", str(budget_file),
        "--out", str(b4_out),
        "--snapshot", str(npm_snapshot)
    ]

    try:
        investigation_main()

        # Score
        sys.argv = [
            "investigation", "score",
            "--prediction", str(b4_out / "prediction.json"),
            "--oracle", str(npm_oracle),
            "--out", str(b4_out / "scores.json")
        ]
        investigation_main()

        scores = json.loads((b4_out / "scores.json").read_text())

        print(f"\n✅ LLM Agent Results:")
        print(f"  Component F1: {scores.get('component_f1', 'N/A')}")
        print(f"  Edge F1: {scores.get('edge_f1', 'N/A')}")
        print(f"  Vulnerability F1: {scores.get('vulnerability_f1', 'N/A')}")

        # Check tool trace
        trace_file = b4_out / "tool-trace.json"
        if trace_file.exists():
            trace = json.loads(trace_file.read_text())
            print(f"  Tool calls: {len(trace.get('steps', []))}")

        return {"status": "SUCCESS", "scores": scores}

    except Exception as e:
        print(f"  Error: {e}")
        return {"status": "FAILED", "error": str(e)}


if __name__ == "__main__":
    print("EAGER-SBOM Pilot Benchmark")
    print("="*60)

    # Run deterministic baselines
    print("\n📊 Phase 1: Deterministic Baselines (B1, B2)")
    baseline_results = run_baseline_comparison()

    # Run LLM agent test
    print("\n🤖 Phase 2: LLM Agent Test (B4)")
    llm_result = run_llm_agent_test()

    print("\n" + "="*60)
    print("Pilot benchmark complete!")
    print("="*60)
