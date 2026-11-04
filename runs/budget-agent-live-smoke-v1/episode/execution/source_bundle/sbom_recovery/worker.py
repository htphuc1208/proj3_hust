"""JSON-lines worker. The container sees allowed evidence and code, never oracle files or the API key."""
import json
from pathlib import Path
import sys

from .agent import ToolBroker, deterministic_policy
from .contracts import TargetContext
from .evidence import EvidenceStore
from .verifier import verify


def main():
    config = json.loads(Path("/input/config.json").read_text())
    context = TargetContext.model_validate(config["context"]) if config["context"] else None
    store = EvidenceStore("/evidence")
    broker = ToolBroker(config["document"], store, context, config["budget"], config["sources"], config["active"], config.get("calibration"))
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if request["kind"] == "tool":
                result = broker.call(request["name"], request["arguments"], request.get("proposals"))
            elif request["kind"] == "finalize":
                result = broker.finalize(request["proposals"])
            elif request["kind"] == "deterministic":
                result = deterministic_policy(broker)
            else:
                raise ValueError("RPC_NOT_ALLOWED")
            response = {"ok": True, "result": result, "trace": broker.trace}
        except Exception as exc:
            response = {"ok": False, "error": type(exc).__name__ + ": " + str(exc), "trace": broker.trace}
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
