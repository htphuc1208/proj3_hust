"""End-to-end budgeted SBOM recovery and post-seal advisory visibility."""
import argparse
import json
from pathlib import Path

from research_core import load, digest
from .budget_agent import run_control, run_budget_agent
from .budget_isolation import BudgetIsolatedBroker
from .budget_sources import prepare_catalog, TrustedReader
from .candidate_risk import assess_risk
from .contracts import TargetContext
from .formats import sha
from .llm import Gateway, GatewayError, read_key
from .storage import save


def recover(input_path, context_path, target, available_at, destination, *, policy="single_agent_reconciliation",
            budget=4, byte_budget=2097152, model="Qwen/Qwen3.6-35B-A3B-FP8", key=None, streaming=False,
            advisory_snapshot=None, code=None, image=None, agent_turns=12):
    out = Path(destination).resolve()
    out.mkdir(parents=True, exist_ok=False)
    observation = load(input_path)
    context = TargetContext.model_validate(load(context_path))
    catalog = prepare_catalog(target, context, available_at)
    save(out / "observation.json", observation)
    save(out / "context.json", context.model_dump())
    save(out / "catalog.json", catalog)
    reader = TrustedReader(target, catalog, context)
    save(out/"progress.json",{"phase":"PREPARING","budget":budget,"source_reads":0})
    def bounded_read(source_id, limit):
        raw = reader.read(source_id,limit)
        save(out/"progress.json",{"phase":"ACQUIRING","budget":budget,"source_reads":len(reader.attempts)})
        return raw
    broker = BudgetIsolatedBroker(observation, context, catalog, bounded_read, out / "execution",
                                 budget=budget, byte_budget=byte_budget, code=code, image=image)
    gateway = None
    try:
        if policy == "single_agent_reconciliation":
            try:
                gateway = Gateway(key, streaming=streaming)
            except GatewayError:
                episode = {"policy": policy, "status": "MODEL_AUTH_UNAVAILABLE", "llm_api_calls": 0,
                           "result": broker.finalize(), "model_requested": model}
            else:
                episode = run_budget_agent(broker, gateway, model, max_turns=agent_turns,
                    on_event=lambda e:save(out/"progress.json",{**e,"source_reads":len(reader.attempts),"budget":budget}))
        else:
            episode = run_control(broker, policy)
        result = episode.pop("result")
        episode.update(budget=budget, catalog_sha256=catalog["sha256"], model_requested=model if gateway else None,
                       evidence_policy="Only bytes returned by charged source RPCs enter the worker",
                       inference_parameters={"max_turns":agent_turns,"max_output_tokens_per_call":2048,
                                             "streaming":streaming,"seed":42},
                       gateway_usage=gateway.calls if gateway else [], gateway_attempts=gateway.requests if gateway else [])
        save(out / "episode.json", episode)
        save(out/"progress.json",{"phase":episode["status"],"source_reads":len(reader.attempts),"budget":budget,
                                  "llm_api_calls":episode["llm_api_calls"]})
        # Confirm output seal before security/advisory knowledge enters this process.
        seal = load(out / "execution/worker/seal.json")
        if seal["prediction_sha256"] != sha(result["document"]) or seal["result_sha256"] != sha(result):
            raise ValueError("Worker output changed before advisory assessment")
        if advisory_snapshot:
            risk = assess_risk(observation, result["document"] if result["validation"]["valid"] else observation,
                               context.root_purls, load(advisory_snapshot))
            risk["candidate_native_valid"] = result["validation"]["valid"]
            risk["prediction_seal_sha256"] = digest(out / "execution/worker/seal.json")
            risk["advisory_file_sha256"] = digest(advisory_snapshot)
            save(out / "risk.json", risk)
        state = load(out / "execution/worker/state.json")
        return {"status": episode["status"], "policy": policy, "llm_api_calls": episode["llm_api_calls"],
                "native_valid": result["validation"]["valid"], "output": str(out),
                "acquisitions": len(reader.attempts), "retractions": len(result["retracted_edges"]),
                "acquisition_attempts":state["attempts"],"acquired_sources":len(state["acquired_source_ids"]),
                "candidate_proposals": len(result["proposals"])}
    finally:
        broker.close()
        if gateway:
            gateway.close()
        save(out / "controller-reader-audit.json", {"read_source_ids": reader.attempts,
             "acquisition_budget": budget, "source_content_reads": len(reader.attempts),
             "oracle_labels_used": False, "trusted_preparation": "All target metadata hashed before inference; no labels or parsed requirements enter the initial catalog"})


def main():
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("input", "context", "target", "available-at", "out"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--policy", choices=["single_agent_reconciliation", "fixed_order", "cheapest_source", "unresolved_priority"], default="single_agent_reconciliation")
    parser.add_argument("--budget", type=int, default=4)
    parser.add_argument("--agent-turns", type=int, default=12)
    parser.add_argument("--byte-budget", type=int, default=2097152)
    parser.add_argument("--model", default="Qwen/Qwen3.6-35B-A3B-FP8")
    parser.add_argument("--ask-key", action="store_true")
    parser.add_argument("--stream", action="store_true")
    parser.add_argument("--advisory-snapshot")
    args = parser.parse_args()
    print(json.dumps(recover(args.input,args.context,args.target,args.available_at,args.out,
        policy=args.policy,budget=args.budget,byte_budget=args.byte_budget,model=args.model,
        key=read_key(args.ask_key),streaming=args.stream,advisory_snapshot=args.advisory_snapshot,agent_turns=args.agent_turns)))


if __name__ == "__main__":
    main()
