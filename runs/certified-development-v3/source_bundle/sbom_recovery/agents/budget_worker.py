"""JSON RPC worker: no target/credential/oracle mounts; source bytes arrive per acquisition."""
import base64
import json
from pathlib import Path
import sys

from .budget_agent import BudgetBroker
from sbom_recovery.core.contracts import TargetContext
from sbom_recovery.core.formats import sha
from sbom_recovery.evidence.storage import save, save_bytes


def main():
    config = json.loads(Path("/input/config.json").read_text())
    context = TargetContext.model_validate(config["context"])
    def reader(source_id, limit):
        print(json.dumps({"kind": "source_request", "source_id": source_id, "limit": limit}), flush=True)
        reply = json.loads(sys.stdin.readline())
        if reply.get("kind") != "source_reply" or reply.get("source_id") != source_id or not reply.get("ok"):
            raise ValueError("BOUNDED_SOURCE_READ_FAILED")
        if len(reply.get("base64", "")) > 4 * ((limit + 2) // 3):
            raise ValueError("SOURCE_REPLY_EXCEEDS_ALLOWANCE")
        return base64.b64decode(reply["base64"], validate=True)
    broker = BudgetBroker(config["document"], context, config["catalog"], reader,
                          budget=config["budget"], byte_budget=config["byte_budget"], max_tools=config["max_tools"],
                          max_source_bytes=config.get('max_source_bytes',262144))
    exported = False
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if request["kind"] == "close":
                break
            if request["kind"] == "call":
                result = broker.call(request["name"], request["arguments"])
            elif request["kind"] == "finalize":
                result = broker.finalize()
            else:
                raise ValueError("RPC_NOT_ALLOWED")
            # Crash-readable state is distinct from the final prediction seal.
            out = Path('/out')
            for source_id, raw in broker.acquired.items():
                if not (out/'acquired'/source_id).exists():
                    save_bytes(out/'acquired'/source_id,raw)
            save(out/'checkpoint.json', {'final':broker.finished,'state':broker.state(),'trace':broker.trace})
            if broker.finished and not exported:
                out = Path("/out")
                for source_id, raw in broker.acquired.items():
                    save_bytes(out / "acquired" / source_id, raw)
                save(out / "trace.json", broker.trace)
                save(out / "state.json", broker.state())
                save(out / "result.json", result)
                save(out / ("recovered.json" if result["validation"]["valid"] else "candidate-invalid.json"), result["document"])
                save(out / "seal.json", {"schema_version": "budget-prediction-seal-v1",
                     "input_sha256": sha(config["document"]), "context_sha256": sha(config["context"]),
                     "catalog_sha256": config["catalog"]["sha256"], "result_sha256": sha(result),
                     "prediction_sha256": sha(result["document"]), "trace_sha256": sha(broker.trace),
                     "state_sha256": sha(broker.state()), "acquired": {k: __import__("hashlib").sha256(v).hexdigest() for k,v in broker.acquired.items()},
                     "reference_labels_read": False, "path_absence_status": "UNKNOWN"})
                exported = True
            response = {"kind": "result", "ok": True, "result": result}
        except Exception as exc:
            response = {"kind": "result", "ok": False, "error_type": type(exc).__name__}
            out=Path('/out')
            for source_id,raw in broker.acquired.items():
                if not (out/'acquired'/source_id).exists():save_bytes(out/'acquired'/source_id,raw)
            save(out/'checkpoint.json',{'final':broker.finished,'state':broker.state(),'trace':broker.trace})
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
