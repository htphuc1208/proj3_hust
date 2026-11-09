"""Bounded tool protocol and deterministic verifier for future model proposals.

The scripted policy exercises the protocol; it is NOT an LLM experiment.
Only observed-node edge repairs are supported. Verification establishes agreement
with the frozen B3 evidence rules, not correctness of registry content or installs.
"""
from copy import deepcopy
import hashlib
import json
import time

from sbom_recovery.metrics.graph_triage import b5_assess
from sbom_recovery.core.research_core import graph, validate_cdx
from sbom_recovery.core.resolver import TargetEnvironment, normalize_purl, run_baseline_b3_context_aware


class ToolDenied(ValueError):
    pass


def verify_proposals(document, resolution, proposals, evidence_hashes):
    nodes, observed = graph(document)
    supported = {}
    for row in resolution["G_candidate"]["edges"]:
        pair = (row["source_purl"], row["target_purl"])
        if (resolution.get("environment_mode") == "single_target" and row["modality"] == "MUST"
                and row["status"] == "INFERRED" and all(node in nodes for node in pair)):
            supported[pair] = row
    accepted, rejected = [], []
    seen = set()
    for proposal in proposals:
        if not isinstance(proposal, dict) or set(proposal) != {"source_purl", "target_purl", "evidence_sha256"}:
            rejected.append({"proposal": proposal, "reason": "INVALID_PROPOSAL_SCHEMA"})
            continue
        if any(not isinstance(value, str) for value in proposal.values()):
            rejected.append({"proposal": proposal, "reason": "INVALID_PROPOSAL_SCHEMA"})
            continue
        pair = (proposal["source_purl"], proposal["target_purl"])
        reason = ("DUPLICATE_PROPOSAL" if pair in seen else "ALREADY_OBSERVED" if pair in observed else
                  "UNOBSERVED_NODE" if not all(node in nodes for node in pair) else
                  "UNSUPPORTED_AMBIGUOUS_OR_CONTRADICTED" if pair not in supported else
                  "EVIDENCE_DIGEST_MISMATCH" if not evidence_hashes.get(pair[0]) or
                  proposal["evidence_sha256"] != evidence_hashes.get(pair[0]) else None)
        seen.add(pair)
        if reason:
            rejected.append({"proposal": proposal, "reason": reason})
        else:
            accepted.append({**proposal, "status": "VERIFIED_CANDIDATE", "basis": supported[pair]})
    return {"accepted": accepted, "rejected": rejected,
            "interpretation": "Verifier agreement with frozen B3 constraints only; candidate edges, not installation proof"}


def repaired_document(document, accepted):
    output = deepcopy(document)
    entities = ([output.get("metadata", {}).get("component")] if output.get("metadata", {}).get("component") else []) + output.get("components", [])
    refs = {normalize_purl(item["purl"]): item["bom-ref"] for item in entities if item.get("purl") and item.get("bom-ref")}
    # Preserve every original declaration; additions may extend nonempty records.
    records = {row["ref"]: row for row in output.setdefault("dependencies", [])}
    for row in accepted:
        source, target = refs[row["source_purl"]], refs[row["target_purl"]]
        if source not in records:
            records[source] = {"ref": source, "dependsOn": []}
            output["dependencies"].append(records[source])
        children = records[source].setdefault("dependsOn", [])
        if target not in children:
            children.append(target)
            children.sort()
    return output


class RepairSession:
    ALLOWED_TOOLS = frozenset({"inspect_graph", "metadata", "resolve", "validate"})

    def __init__(self, document, provider, context, max_tool_calls=64):
        if max_tool_calls < 1:
            raise ValueError("Positive tool budget required")
        self.document = deepcopy(document)
        self.provider = provider
        self.context = context
        self.max_tool_calls = max_tool_calls
        self.trace = []
        self.resolution = None
        self.nodes, _ = graph(document)
        self.evidence_hashes = {f"pkg:pypi/{item['name']}@{item['version']}": item["sha256"]
                                for item in provider.manifest["artifacts"] if item.get("sha256")}

    def call(self, name, arguments=None):
        arguments = arguments or {}
        if name not in self.ALLOWED_TOOLS:
            raise ToolDenied("Tool is not allowed: " + name)
        if len(self.trace) >= self.max_tool_calls:
            raise ToolDenied("Tool-call budget exhausted")
        started = time.perf_counter()
        record = {"call": len(self.trace) + 1, "tool": name, "arguments": deepcopy(arguments)}
        try:
            result = self._dispatch(name, arguments)
            encoded = json.dumps(result, sort_keys=True, default=lambda value: sorted(value) if isinstance(value, set) else str(value))
            record.update(status="OK", output=result, output_sha256=hashlib.sha256(encoded.encode()).hexdigest())
            return result
        except Exception as exc:
            record.update(status="ERROR", error=str(exc))
            raise
        finally:
            record["duration_seconds"] = time.perf_counter() - started
            self.trace.append(record)

    def _dispatch(self, name, arguments):
        if name == "inspect_graph":
            if arguments:
                raise ToolDenied("inspect_graph takes no arguments")
            return b5_assess(self.document)
        if name == "metadata":
            if set(arguments) != {"purl"} or arguments["purl"] not in self.nodes:
                raise ToolDenied("Metadata query must name an observed exact identity")
            purl = arguments["purl"]
            key = purl.removeprefix("pkg:pypi/")
            record = self.provider.packages.get(key)
            available = self.provider.get_requirements(purl) is not None
            return {"purl": purl, "status": "AVAILABLE" if available else "EVIDENCE_UNAVAILABLE",
                    "metadata": deepcopy(record), "sha256": self.evidence_hashes.get(purl),
                    "content_role": "UNTRUSTED_PACKAGE_DATA"}
        if name == "resolve":
            if arguments:
                raise ToolDenied("resolve takes no arguments; context is frozen by the runner")
            env = TargetEnvironment(**{**self.context, "active_extras": set(self.context.get("active_extras", []))}) if self.context else None
            self.resolution = run_baseline_b3_context_aware(self.document, self.provider, target_env=env)
            return self.resolution
        if set(arguments) != {"proposals"} or not isinstance(arguments["proposals"], list):
            raise ToolDenied("validate requires a proposals array")
        if self.resolution is None:
            raise ToolDenied("Call resolve before validate")
        result = verify_proposals(self.document, self.resolution, arguments["proposals"], self.evidence_hashes)
        result["candidate_document"] = repaired_document(self.document, result["accepted"])
        result["schema_validation"] = validate_cdx(result["candidate_document"])
        if not result["schema_validation"]["valid"]:
            raise ValueError("Candidate output failed CycloneDX validation")
        return result


def scripted_policy(session):
    """Fixed-order tooling smoke run; no model, learning, or API spending."""
    session.call("inspect_graph")
    # Inspect frozen parent records only. No acquisition, shell, or arbitrary path tool.
    for purl in sorted(session.nodes):
        session.call("metadata", {"purl": purl})
    resolution = session.call("resolve")
    _, observed = graph(session.document)
    proposals = [{"source_purl": row["source_purl"], "target_purl": row["target_purl"],
                  "evidence_sha256": session.evidence_hashes.get(row["source_purl"], "")}
                 for row in resolution["G_candidate"]["edges"]
                 if row["modality"] == "MUST" and row["status"] == "INFERRED"
                 and (row["source_purl"], row["target_purl"]) not in observed]
    verified = session.call("validate", {"proposals": proposals})
    return {"policy": "SCRIPTED_FIXED_ORDER_TOOL_PROTOCOL_SMOKE", "llm_experiment": "NOT_RUN_NO_API_CREDENTIAL",
            "model_api_calls": 0, "tokens": None, "model_cost": None, "proposals": proposals,
            "verified": verified, "trace": session.trace, "tool_calls": len(session.trace),
            "max_tool_calls": session.max_tool_calls,
            "b3_predicted_edges": sorted(resolution["predicted_edges"]),
            "unresolved": resolution["unresolved"]}
