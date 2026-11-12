"""Runnable investigation, scorer and controlled demonstration commands."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .models import Budget


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m sbom_recovery investigation")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Investigate multiple SBOMs without evaluation labels")
    run.add_argument("--request", required=True)
    run.add_argument("--out", required=True)
    run.add_argument("--policy", choices=["observed", "deterministic", "rule", "agent", "fixed_llm"], default="rule")
    run.add_argument("--budget", help="Frozen JSON resource and price settings")
    run.add_argument("--model")
    run.add_argument("--base-url")
    run.add_argument("--replay", help="Recorded actions; always labeled replay, never a live LLM result")
    run.add_argument("--metadata-only", action="store_true")
    run.add_argument("--graph-only", action="store_true")
    run.add_argument("--snapshot", help="Frozen OSV snapshot; no network lookup")
    run.add_argument("--advisory", action="append", default=[], help="Focus acquisition on a public advisory ID or alias")
    score = sub.add_parser("score", help="Scorer-only sealed-oracle evaluation")
    score.add_argument("--prediction", required=True)
    score.add_argument("--oracle", required=True)
    score.add_argument("--out", required=True)
    demo = sub.add_parser("demo", help="Create controlled npm/Cargo examples with separately stored oracles")
    demo.add_argument("--out", required=True)
    study = sub.add_parser("study", help="Run frozen case comparisons, seal all predictions, then score")
    study.add_argument("--manifest", required=True)
    study.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    read = lambda path: json.loads(Path(path).read_text())
    if args.command == "run":
        from .runner import investigate, save_run
        from .planner import GatewayPlanner, ReplayPlanner
        if args.metadata_only and args.graph_only:
            parser.error("Select at most one ablation")
        budget = Budget.model_validate(read(args.budget)) if args.budget else Budget()
        planner = None
        if args.replay:
            planner = ReplayPlanner(read(args.replay))
        elif args.policy in {"agent", "fixed_llm"}:
            planner = GatewayPlanner(args.model, base_url=args.base_url)
        try:
            snapshot = read(args.snapshot) if args.snapshot else None
            run_result = investigate(read(args.request), Path(args.request).resolve().parent,
                policy=args.policy, budget=budget, planner=planner,
                metadata=not args.graph_only, graph=not args.metadata_only,
                advisory_snapshot=snapshot, advisory_ids=args.advisory)
            result = save_run(run_result, args.out, snapshot=snapshot)
        finally:
            if planner and hasattr(planner, "close"):
                planner.close()
    elif args.command == "score":
        from .evaluation import score_files
        result = score_files(args.prediction, args.oracle)
        out = Path(args.out)
        if out.exists():
            raise ValueError("Use a fresh evaluation output path")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    elif args.command == "demo":
        from .demo import create_demo
        result = create_demo(args.out)
    else:
        from .study import run_study
        result = run_study(args.manifest, args.out)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
