"""Application entrypoint for a user's SBOM, independent of the benchmark oracle."""
from pathlib import Path

from research_core import load, save, now, digest
from .agent import deterministic_policy, run_agent
from .contracts import TargetContext
from .evidence import EvidenceStore
from .formats import NativeDocument, package_purl, sha, cyclonedx_projection, validate_native
from .isolated import IsolatedBroker
from .llm import Gateway
from .storage import save
from .targets import metadata_inventory


def recover(input_file, destination, *, context_file=None, target=None, evidence=None,
            policy="deterministic", active=False, budget=64, model=None, key=None, streaming=False):
    out = Path(destination).resolve()
    out.mkdir(parents=True, exist_ok=False)
    document = load(input_file)
    native = NativeDocument(document)
    context = TargetContext.model_validate(load(context_file)) if context_file else None
    store = EvidenceStore(out / "evidence")
    if evidence:
        supplied = EvidenceStore(evidence)
        try:
            # Import only digest-checked records, not arbitrary filesystem paths supplied by the model.
            for payload in supplied.manifest()["records"]:
                _, raw = supplied.read(payload["evidence_id"])
                store.import_record(payload, raw)
        finally:
            supplied.close()
    sources = {}
    if target:
        if context is None:
            raise ValueError("Target metadata needs an explicit context and matching target_id")
        root = Path(target).resolve()
        paths, inventory_digest = metadata_inventory(root)
        if context.target_id != inventory_digest:
            raise ValueError("Target metadata inventory digest does not match context")
        for p in paths:
            if p.parent.parent.name not in {"site-packages", "dist-packages"}:
                continue
            raw = p.read_bytes()
            source = "target:" + str(p.relative_to(root))
            key_id = sha(source)
            sources[key_id] = {"kind": "target_metadata", "path": str(p), "description": source,
                               "content_binding": sha({"raw_hex": raw.hex()}), "available_at": context.evidence_cutoff,
                               "availability_kind": "UPPER_BOUND"}
            if not active:
                store.add(raw, source=source, kind="target_metadata", target_id=context.target_id,
                          authority="VERIFIED_TARGET", available_at=context.evidence_cutoff, availability_kind="UPPER_BOUND")
    for _, item in native.packages().items():
        purl = package_purl(item, native.format)
        if purl and purl.startswith("pkg:pypi/"):
            sources[sha(purl)] = {"kind": "registry", "description": purl, "purl": purl}
    save(out / "input.json", document)
    save(out / "context.json", context.model_dump() if context else None)
    save(out / "initial_evidence_manifest.json", store.manifest())
    broker = IsolatedBroker(document, store, context, budget, sources, active)
    client = None
    broker_closed = False
    try:
        if policy == "deterministic":
            result = broker.deterministic()
        else:
            if not model:
                raise ValueError("LLM policy requires a preflight-verified --model")
            client = Gateway(key, streaming=streaming)
            result = run_agent(broker, client, model, multi=policy == "multi_agent",
                               on_event=lambda e: save(out / f"turn-{e['turn']:03d}.json", e))
        result["isolation"] = broker.audit
        broker.close()
        broker_closed = True
        verified = result["verified"]
        save(out / "result.json", result)
        save(out / "candidates.json", {"supported": verified["supported"], "rejected": verified["rejected"]})
        if native.format == "spdx":
            save(out / "recovered.spdx.json", verified["document"])
        cdx, mapping = cyclonedx_projection(verified["document"], context.root_purls if context else [])
        validation = validate_native(cdx)
        save(out / ("recovered.cdx.json" if validation["valid"] else "candidate-invalid.cdx.json"), cdx)
        save(out / "conversion_audit.json", mapping)
        save(out / "cyclonedx_validation.json", validation)
        return {"status": result["status"], "accepted_changes": len(verified["accepted"]),
                "supported_changes": len(verified["supported"]), "rejected_changes": len(verified["rejected"]),
                "cyclonedx_valid": validation["valid"], "input_sha256": digest(input_file), "output": str(out),
                "verification_scope": "target metadata declarations, not executable contents or runtime behavior"}
    finally:
        if not broker_closed:
            broker.close()
        save(out / "evidence_manifest.json", store.manifest())
        store.close()
        if client:
            client.close()
