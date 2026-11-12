"""Public-bundle inference subprocess; no oracle/evaluator import or argument."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import sys


def install_read_boundary(bundle, output, *, live=False):
    """Limit Python file/socket/process events; not an OS execution sandbox."""
    bundle, output = Path(bundle).resolve(), Path(output).resolve()
    root = Path(__file__).resolve().parents[2]
    library_roots = {Path(sys.base_prefix).resolve() / "lib", Path(sys.prefix).resolve() / "lib"}
    schema_root = root / "research/schemas"

    def under(path, directory):
        return path == directory or directory in path.parents

    def audit(event, args):
        if event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "pty.spawn"}:
            raise PermissionError("Inference cannot execute child programs")
        if event in {"socket.connect", "socket.getaddrinfo", "socket.bind"} and not live:
            raise PermissionError("Offline inference cannot access the network")
        if event != "open" or isinstance(args[0], int):
            return
        raw_path, mode, flags = args
        if not isinstance(raw_path, (str, bytes, os.PathLike)):
            raise PermissionError("Unknown file handle")
        path = Path(os.fsdecode(raw_path)).absolute()
        # Lexical roots avoid recursive filesystem opens within the audit hook.
        write = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (isinstance(flags, int) and bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)))
        if write:
            if under(path, output):
                return
            raise PermissionError("Inference writes are confined to its output directory")
        if under(path, bundle) or under(path, output) or any(under(path, p) for p in library_roots):
            return
        if under(path, root) and (path.suffix in {".py", ".pyc", ".so"} or under(path, schema_root)):
            return
        if live and (under(path, Path("/etc/ssl")) or under(path, Path("/usr/share/ca-certificates"))):
            return
        raise PermissionError("Inference read outside staged public bundle and installed code")
    sys.addaudithook(audit)


def _limits(seconds):
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (math.ceil(seconds) + 10, math.ceil(seconds) + 10))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    except (ImportError, OSError, ValueError):
        pass


def _unifier(request, bundle):
    """Call the pinned upstream implementation, never a local substitute."""
    from sbom_recovery.baselines.baselines import merge
    from .engine import ingest, reconcile
    from .runner import fingerprint
    state = ingest(request, bundle)
    if any(row["format"] != "SPDX" for row in state["source_documents"]):
        return None, {"status": "UNSUPPORTED", "reason": "Original sbom-unifier requires native SPDX; no implicit conversion"}
    try:
        merged, provenance = merge([(r["source_id"], r["document"]) for r in state["source_documents"]])
    except (ValueError, OSError, ImportError) as exc:
        return None, {"status": "UNSUPPORTED", "reason": "Pinned upstream unavailable or unsupported", "error_type": type(exc).__name__}
    # Re-ingest the real merged document through the same lossless observation
    # contract, retaining an UNKNOWN verification state for source assertions.
    raw = (json.dumps(merged, sort_keys=True) + "\n").encode()
    generated = Path(bundle) / "generated/upstream.spdx.json"
    generated.parent.mkdir()
    generated.write_bytes(raw)
    copy = request.model_dump()
    for row in copy["documents"]:
        row["document"] = {"path": "generated/upstream.spdx.json", "sha256": hashlib.sha256(raw).hexdigest()}
        row["format"] = "SPDX"
    prediction = reconcile(ingest(copy, bundle), [], metadata=False, graph=False)
    prediction.update(schema_version="sbom-investigation-result-v1", policy="sbom_unifier", status="COMPLETE",
                      investigation={"upstream": provenance, "tool_calls": 0, "bytes_used": 0, "model_records": []})
    return {"prediction": prediction, "tool_trace": [], "transcript": [], "acquired": [],
            "request_sha256": fingerprint(request.model_dump())}, None


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    bundle = Path.cwd()
    output = Path(config["out"])
    method = config["method"]
    _limits(config["budget"]["max_seconds"])
    if config.get("audit", True):
        install_read_boundary(bundle, output, live=method in {"agent", "fixed_llm"})
    from sbom_recovery.reconciliation.merge_contracts_v3 import ReconciliationRequestV3
    from .models import Budget
    from .runner import investigate, save_run
    request = ReconciliationRequestV3.model_validate_json((bundle / config["request"]).read_text())
    planner = None
    if method in {"agent", "fixed_llm"}:
        from .planner import GatewayPlanner, PlanningError
        try:
            planner = GatewayPlanner(config["model"], base_url=config.get("model_base_url"), seed=config["seed"])
        except PlanningError:
            print(json.dumps({"status": "UNSUPPORTED", "reason": "Frozen live model credential or configuration unavailable"}))
            return
    try:
        if method == "sbom_unifier":
            run, unsupported = _unifier(request, bundle)
            if unsupported:
                print(json.dumps(unsupported))
                return
        elif method in {"naive_union", "fixed_priority", "majority", "lockfile_only"} or method.startswith("single:"):
            from .baseline import baseline
            from .engine import ingest
            from .broker import fingerprint
            from .evidence import EvidenceCatalog
            import time
            started = time.monotonic()
            acquired = list(config.get("initial_evidence", []))
            trace, used_bytes = [], 0
            if method == "lockfile_only" and not config.get("fixed_evidence"):
                catalog = EvidenceCatalog(request, bundle)
                for item in sorted(catalog.descriptors(), key=lambda d: d["source_id"]):
                    if item["kind"] not in {"lockfile", "native_resolution"}:
                        continue
                    if len(trace) >= config["budget"]["max_tool_calls"] or used_bytes >= config["budget"]["max_bytes"] or time.monotonic() - started >= config["budget"]["max_seconds"]:
                        break
                    response = catalog.acquire(item["source_id"], config["budget"]["max_bytes"] - used_bytes)
                    used_bytes += response["bytes_returned"]
                    acquired.append(response)
                    trace.append({"action": {"action": "acquire", "source_id": item["source_id"]}, "response": response})
            prediction = baseline(ingest(request, bundle), method, acquired)
            prediction.update(schema_version="sbom-investigation-result-v1", policy=method, status="COMPLETE",
                investigation={"usage": {"tool_calls": len(trace), "bytes": used_bytes, "seconds": time.monotonic() - started},
                               "oracle_access": False, "budget": config["budget"]})
            run = {"prediction": prediction, "tool_trace": trace, "transcript": [], "acquired": acquired,
                   "request_sha256": fingerprint(request.model_dump())}
        else:
            policy = "rule" if method in {"metadata_only", "graph_only"} else method
            run = investigate(request, bundle, policy=policy, budget=Budget.model_validate(config["budget"]),
                planner=planner, metadata=method != "graph_only", graph=method != "metadata_only",
                initial_evidence=config.get("initial_evidence", []), fixed_evidence=config.get("fixed_evidence", False),
                advisory_snapshot=config.get("advisory_snapshot"), advisory_ids=config.get("advisory_ids", []))
        precollection = config.get("precollection")
        run["prediction"].setdefault("investigation", {})["original_study_budget"] = config.get("original_budget", config["budget"])
        if precollection:
            investigation = run["prediction"].setdefault("investigation", {})
            investigation["precollection"] = precollection
            if precollection.get("charged_to_arm"):
                usage = investigation.setdefault("usage", {})
                usage["tool_calls"] = usage.get("tool_calls", 0) + precollection["calls"]
                usage["bytes"] = usage.get("bytes", 0) + precollection["bytes"]
                usage["seconds"] = usage.get("seconds", 0) + precollection.get("seconds", 0)
        saved = save_run(run, output, snapshot=config.get("advisory_snapshot"))
        print(json.dumps({"status": "PREDICTED", "prediction_status": saved["status"],
                          "isolation": "STAGED_SUBPROCESS_WITH_PYTHON_AUDIT_HOOK" if config.get("audit", True)
                                       else "STAGED_SUBPROCESS_PINNED_UPSTREAM_NO_AUDIT"}))
    finally:
        if planner:
            planner.close()


if __name__ == "__main__":
    main()
