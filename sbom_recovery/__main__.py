"""Research CLI. Large campaigns are resumable; test phase requires frozen model selection."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)

from research_core import digest, load, now, save
from .baselines import reproduce
from .campaign import run_case, source_comparison, summarize
from .capture import capture_cohort
from .cohort import acquire, replace_build_failures
from .isolated import build_worker_image
from .llm import Gateway, read_key
from .storage import save


def main():
    parser = argparse.ArgumentParser(prog="python -m sbom_recovery")
    commands = parser.add_subparsers(dest="command", required=True)
    r = commands.add_parser("reconcile", help="Reconcile target-bound declared edges with per-edge explanations")
    for name in ("input", "context", "evidence", "out"):
        r.add_argument("--" + name, required=True)
    r = commands.add_parser("reconcile-collect", help="Collect location-bound installed METADATA without reading labels")
    for name in ("input", "context", "target", "available-at", "out"):
        r.add_argument("--" + name, required=True)
    for command in ("gold-build", "gold-validate", "pilot-e1"):
        r = commands.add_parser(command, help="Content-bound multi-ecosystem pilot v2")
        r.add_argument("--case", required=True)
        r.add_argument("--out", required=True)
        if command == "gold-validate":
            r.add_argument("--gold", required=True)
    r = commands.add_parser("gold-review-export", help="Export source-bound packets for two independent human reviewers")
    r.add_argument("--run", required=True)
    r.add_argument("--out", required=True)
    r = commands.add_parser("gold-review-check", help="Validate submitted human reviews without changing labels")
    r.add_argument("--packet", required=True)
    r.add_argument("--reviews", nargs="+", required=True)
    r.add_argument("--out", required=True)
    r = commands.add_parser("gold-scope-audit", help="Compare permitted candidate coordinates without promoting source inventory to runtime scope")
    r.add_argument("--case", required=True)
    r.add_argument("--out", required=True)
    commands.add_parser("bootstrap", help="Fetch and verify the pinned upstream tools")
    r = commands.add_parser("reproduce", help="Reproduce the original 90-project coverage CSVs")
    r.add_argument("--out", required=True)
    r = commands.add_parser("preflight", help="Probe actual gateway capabilities; credentials stay out of files")
    r.add_argument("--out", required=True)
    r.add_argument("--models", nargs="+")
    r.add_argument("--ask-key", action="store_true")
    r.add_argument("--stream", action="store_true", help="Probe SSE transport instead of the default non-streaming transport")
    r = commands.add_parser("cohort", help="Freeze 20/20/60 chronological project selection")
    r.add_argument("--out", required=True)
    r.add_argument("--workers", type=int, default=12)
    r = commands.add_parser("capture", help="Pin and install selected projects, capture independent labels and real scanners")
    r.add_argument("--cohort", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--limit", type=int)
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--no-source", action="store_true")
    r = commands.add_parser("references", help="Evaluation-only full installed references from frozen pip inspect")
    r.add_argument("--captures", required=True)
    r.add_argument("--out", required=True)
    r = commands.add_parser("validate-cohort")
    r.add_argument("--cohort", required=True)
    r.add_argument("--captures", required=True)
    r.add_argument("--out", required=True)
    r = commands.add_parser("replace-build-failures", help="Use only build validity, never recovery scores, to select fixed-ranked reserves")
    r.add_argument("--cohort", required=True)
    r.add_argument("--captures", required=True)
    r.add_argument("--out", required=True)
    commands.add_parser("build-worker", help="Build and freeze the prediction container")
    r = commands.add_parser("recover", help="Recover a native SBOM with evidence; no oracle argument exists")
    r.add_argument("--input", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--context")
    r.add_argument("--target")
    r.add_argument("--evidence")
    r.add_argument("--policy", choices=["deterministic","single_agent","multi_agent"], default="deterministic")
    r.add_argument("--active", action="store_true")
    r.add_argument("--budget", type=int, default=64)
    r.add_argument("--model")
    r.add_argument("--ask-key", action="store_true")
    r.add_argument("--stream", action="store_true", help="Use SSE for this standalone recovery; frozen benchmarks retain their original transport")
    r = commands.add_parser("benchmark", help="Run paired baseline/LLM experiments in oracle-blind containers")
    r.add_argument("--cohort", required=True)
    r.add_argument("--captures", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--phase", choices=["pilot", "development", "calibration", "test"], required=True)
    r.add_argument("--projects", nargs="+")
    r.add_argument("--methods", nargs="+", default=["observed", "single_scanner", "sbom_unifier", "unifier_rules", "deterministic", "single_agent", "multi_agent"])
    r.add_argument("--conditions", nargs="+", choices=["fixed", "active"], default=["fixed", "active"])
    r.add_argument("--families", nargs="+", choices=["raw", "component", "metadata", "dependency"], default=["raw", "component", "metadata", "dependency"])
    r.add_argument("--mask-origin", choices=["reference", "scanner"], default=None,
                   help="Calibration/test default to independent-reference masks; development defaults to scanner corruption")
    r.add_argument("--rates", nargs="+", type=float, default=[0.1, 0.3, 0.5, 0.7])
    r.add_argument("--seeds", nargs="+", type=int, default=[11, 23, 42])
    r.add_argument("--budgets", nargs="+", type=int, default=[64])
    r.add_argument("--repetitions", type=int, default=3)
    r.add_argument("--max-turns", type=int, default=64)
    r.add_argument("--workers", type=int, default=1, choices=[1,2,3,4])
    r.add_argument("--model")
    r.add_argument("--selection", help="Frozen development model-selection JSON; mandatory for test LLM runs")
    r.add_argument("--single-scanner", choices=["syft","trivy"], default=None)
    r.add_argument("--ask-key", action="store_true")
    r.add_argument("--stream", action="store_true", help="Use SSE transport for LLM calls")
    r = commands.add_parser("source-coverage", help="Run original source-SBOM integration and native field coverage")
    r.add_argument("--captures", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--workers", type=int, default=4, choices=[1,2,3,4])
    r = commands.add_parser("summarize")
    r.add_argument("--run", required=True)
    r.add_argument("--include-development", action="store_true")
    r = commands.add_parser("report")
    r.add_argument("--run", required=True)
    r.add_argument("--out", required=True)
    r = commands.add_parser("select-model")
    r.add_argument("--runs", nargs="+", required=True)
    r.add_argument("--cohort", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--captures")
    r = commands.add_parser("osv-snapshot", help="Evaluation-only retrospective OSV snapshot")
    r.add_argument("--cohort", required=True)
    r.add_argument("--captures", required=True)
    r.add_argument("--out", required=True)
    r = commands.add_parser("security-score", help="Measure confirmed Level-1 advisory-path recovery")
    r.add_argument("--run", required=True)
    r.add_argument("--captures", required=True)
    r.add_argument("--snapshot", required=True)
    args = parser.parse_args()
    if args.command == "reconcile":
        from .reconciliation.certified_reconciliation import run
        result = run(args.input, args.context, args.evidence, args.out)
    elif args.command == "reconcile-collect":
        from .reconciliation.contracts_v2 import ContextKnowledgeV2
        from .reconciliation.certified_evidence import collect_evidence
        context = ContextKnowledgeV2.model_validate_json(Path(args.context).read_text())
        manifest = collect_evidence(load(args.input), context, args.target, args.available_at, args.out)
        result = {"sources": len(manifest.sources), "bindings": len(manifest.bindings),
                  "manifest": str(Path(args.out) / "manifest.json"), "reference_labels_read": False}
    elif args.command == "gold-scope-audit":
        from .scope_audit import audit_scopes
        result = audit_scopes(args.case, args.out)
    elif args.command == "gold-review-export":
        from .gold_review import export_reviews
        result = export_reviews(args.run, args.out)
    elif args.command == "gold-review-check":
        from .gold_review import check_reviews
        result = check_reviews(args.packet, args.reviews, args.out)
    elif args.command == "gold-build":
        from .gold_pipeline import build_gold
        result = build_gold(args.case, args.out)
    elif args.command == "gold-validate":
        from .gold_contracts import LedgerV2
        from .gold_pipeline import validate_gold
        result = validate_gold(args.case, LedgerV2.model_validate_json(Path(args.gold).read_text()))
        if Path(args.out).exists():
            raise ValueError("Use a fresh validation output path")
        save(args.out, result)
    elif args.command == "pilot-e1":
        from .gold_pilot import run_e1
        result = run_e1(args.case, args.out)
    elif args.command == "bootstrap":
        from .bootstrap import bootstrap
        result = bootstrap()
    elif args.command == "reproduce":
        result = reproduce(args.out)
    elif args.command == "preflight":
        client = Gateway(read_key(args.ask_key), streaming=args.stream)
        try:
            result = client.preflight(args.models)
            save(args.out, result)
        finally:
            client.close()
    elif args.command == "cohort":
        result = acquire(args.out, workers=args.workers)
    elif args.command == "capture":
        result = capture_cohort(args.cohort, args.out, args.limit, args.workers, not args.no_source)
    elif args.command == "references":
        from .references import materialize
        result = materialize(args.captures)
        save(args.out, result)
    elif args.command == "validate-cohort":
        from .validation import validate_cohort
        result = validate_cohort(args.cohort, args.captures)
        save(args.out, result)
    elif args.command == "replace-build-failures":
        result = replace_build_failures(args.cohort, args.captures, args.out)
    elif args.command == "build-worker":
        result = {"image": build_worker_image()}
    elif args.command == "recover":
        from .recover import recover
        result = recover(args.input, args.out, context_file=args.context, target=args.target, evidence=args.evidence,
                         policy=args.policy, active=args.active, budget=args.budget, model=args.model,
                         key=read_key(args.ask_key) if args.policy != "deterministic" else None, streaming=args.stream)
    elif args.command == "source-coverage":
        from concurrent.futures import ProcessPoolExecutor, as_completed
        from .campaign import source_comparison_job
        rows = []
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(source_comparison_job, str(p.parent), str(Path(args.out) / p.parent.name))
                       for p in sorted(Path(args.captures).glob("*/capture.json")) if load(p)["status"] == "COMPLETE"]
            for future in as_completed(futures):
                item = future.result()
                rows.append(item)
                print(json.dumps({"project": item["project"], "status": item["status"]}), flush=True)
                save(Path(args.out) / "progress.json", {"completed": len(rows), "total": len(futures)})
        result = {"records": rows, "source_scope_only": True}
        save(Path(args.out) / "source_summary.json", result)
    elif args.command == "summarize":
        result = summarize(args.run, not args.include_development)
    elif args.command == "report":
        from .reporting import report
        result = report(args.run, args.out)
    elif args.command == "select-model":
        from .selection import select_model
        result = select_model(args.runs, args.cohort, args.out, args.captures)
    elif args.command == "osv-snapshot":
        from .security import osv_snapshot
        from .metrics import graph_facts
        purls = set()
        for project in load(args.cohort)["projects"]:
            reference = Path(args.captures) / project["name"] / "oracle/installed_reference.cdx.json"
            if reference.exists():
                purls.update(graph_facts(load(reference))[0])
        result = osv_snapshot(purls, args.out)
    elif args.command == "security-score":
        from .security import score_campaign_security
        result = score_campaign_security(args.run, args.captures, args.snapshot)
    else:
        result = benchmark(args)
    print(json.dumps({k: v for k, v in result.items() if k not in {"records", "projects", "config", "probes", "models"}}, ensure_ascii=False), flush=True)


def benchmark(args, *, secret=None):
    cohort = load(args.cohort)
    config = cohort["config"]
    args.mask_origin = getattr(args, "mask_origin", None) or ("scanner" if args.phase in {"pilot", "development"} else "reference")
    if args.repetitions < 1 or not 1 <= args.max_turns <= config["max_model_turns"]:
        raise ValueError("Invalid repetition/turn count")
    if any(b not in config["tool_budgets"] for b in args.budgets):
        raise ValueError("Unregistered tool budget")
    llm = any("agent" in method for method in args.methods)
    if args.phase in {"calibration", "test"} and llm:
        if not args.selection:
            raise ValueError("Calibration/test LLM runs require frozen --selection from development")
        selection = load(args.selection)
        if selection.get("status") != "FROZEN" or selection["cohort_sha256"] != digest(args.cohort):
            raise ValueError("Model selection is not frozen for this cohort")
        if args.model and args.model != selection["model"]:
            raise ValueError("Model differs from frozen development selection")
        args.model = selection["model"]
        frozen_scanner = selection.get("single_scanner", "syft")
        if args.single_scanner and args.single_scanner != frozen_scanner:
            raise ValueError("Scanner differs from frozen development selection")
        args.single_scanner = frozen_scanner
    args.single_scanner = args.single_scanner or "syft"
    if llm and not args.model:
        raise ValueError("Pass a preflight-verified model ID")
    target_partition = "development" if args.phase == "pilot" else args.phase
    projects = [r for r in cohort["projects"] if r["partition"] == target_partition]
    if args.projects:
        if set(args.projects) - {r["name"] for r in projects}:
            raise ValueError("Requested projects are absent from the selected partition; pilot uses development only")
        projects = [r for r in projects if r["name"] in args.projects]
    if not projects:
        raise ValueError("No projects selected")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    settings = {k: v for k, v in vars(args).items() if k != "ask_key"}
    settings.update(cohort_sha256=digest(args.cohort), protocol_sha256=cohort["protocol_sha256"])
    from .freeze import freeze
    settings["source_sha256"] = freeze(out / "source_bundle")
    manifest = out / "campaign.json"
    if manifest.exists() and load(manifest)["settings"] != settings:
        raise ValueError("Campaign config changed; use another output directory")
    save(manifest, {"status": "RUNNING", "settings": settings, "started_at": now(), "independent_selected_projects": len(projects),
                    "controller_pid": os.getpid(),
                    "data_kind": "ENGINEERING_PILOT" if args.phase == "pilot" else "EMPIRICAL_WITH_SEPARATE_CONTROLLED_MASKS"})
    secret = (secret if secret is not None else read_key(args.ask_key)) if llm else None
    client = Gateway(secret, streaming=getattr(args, "stream", False)) if llm and args.workers == 1 else None
    records, skipped = [], []
    jobs = []
    try:
        for project in projects:
            capture = Path(args.captures) / project["name"]
            if not (capture / "capture.json").exists() or load(capture / "capture.json")["status"] != "COMPLETE":
                skipped.append({"project": project["name"], "reason": "CAPTURE_UNAVAILABLE"})
                continue
            for condition in args.conditions:
                for family in args.families:
                    for rate in ([0.] if family == "raw" else args.rates):
                        for seed in ([11] if family == "raw" else args.seeds):
                            for budget in args.budgets:
                                for repetition in range(args.repetitions if llm else 1):
                                    case = out / project["name"] / condition / f"{family}-{rate:g}-{seed}" / f"budget-{budget}" / f"rep-{repetition}"
                                    if args.workers > 1:
                                        jobs.append({"capture_dir": str(capture), "destination": str(case), "condition": condition,
                                            "family": family, "rate": rate, "mask_seed": seed, "methods": args.methods,
                                            "budget": budget, "model": args.model, "repetition": repetition, "max_turns": args.max_turns})
                                        jobs[-1]["single_scanner"] = args.single_scanner
                                        jobs[-1]["mask_origin"] = args.mask_origin
                                        jobs[-1]["streaming"] = getattr(args, "stream", False)
                                        continue
                                    result = run_case(capture, case, condition=condition, family=family, rate=rate, mask_seed=seed,
                                        methods=args.methods, budget=budget, model=args.model, gateway=client,
                                        repetition=repetition, max_turns=args.max_turns,
                                        single_scanner=args.single_scanner, mask_origin=args.mask_origin)
                                    save(case / "records.json", result)
                                    records.extend(result.get("records", []))
        if jobs:
            from concurrent.futures import ProcessPoolExecutor, as_completed
            from .campaign import run_case_job
            # Spread early checkpoints across projects. Repetitions remain nested
            # observations; this changes execution order, never the case matrix.
            jobs.sort(key=lambda j: (j["repetition"], j["family"], j["rate"], j["mask_seed"],
                                     j["condition"], j["budget"], Path(j["capture_dir"]).name))
            with ProcessPoolExecutor(max_workers=args.workers) as pool:
                futures = [pool.submit(run_case_job, job, secret) for job in jobs]
                for index, future in enumerate(as_completed(futures), 1):
                    records.extend(future.result().get("records", []))
                    save(out / "progress.json", {"completed_cases": index, "total_cases": len(jobs),
                                                "independent_projects": len({r['project'] for r in records}), "updated_at": now()})
        summary = {"status": "COMPLETE" if not skipped and not any(r.get("status", "COMPLETE") != "COMPLETE" for r in records) else "PARTIAL",
                   "records": records, "skipped": skipped, "settings": settings, "completed_at": now(),
                   "independent_projects": len({r["project"] for r in records}), "claim": "UNASSESSED_PENDING_STATISTICS_AND_VALIDITY_REVIEW"}
        save(manifest, summary)
        summarize(out)
        return summary
    except BaseException as exc:
        save(manifest, {"status": "INTERRUPTED" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else "FAILED",
            "settings": settings, "updated_at": now(), "controller_pid": os.getpid(),
            "error_type": type(exc).__name__, "error": str(exc), "records": records, "skipped": skipped})
        raise
    finally:
        if client:
            client.close()


if __name__ == "__main__":
    main()
