#!/usr/bin/env python3
"""Copy only blinded discovery evidence; never fill human reviews."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sbom_recovery.gold_contracts import contained, fingerprint
from sbom_recovery.storage import save


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviews", default="runs/gold-pilot-v3/reviews")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    source, out = Path(args.reviews), Path(args.out)
    packet = json.loads((source / "discovery-packet.json").read_text())
    checked = dict(packet)
    claimed = checked.pop("packet_sha256")
    if fingerprint(checked) != claimed:
        raise ValueError("Changed discovery packet")
    out.mkdir(parents=True, exist_ok=False)
    mapping = []
    for task in packet["tasks"]:
        root = Path(packet["contexts"][task["case_id"]]["evidence_root"])
        for key, entry in task["allowed_evidence"].items():
            if entry["kind"] not in {"source", "manifest", "artifact"}:
                raise ValueError("Machine/label inventory cannot enter discovery")
            src = contained(root, entry["path"])
            digest = hashlib.sha256(src.read_bytes()).hexdigest()
            if digest != entry["sha256"]:
                raise ValueError("Changed discovery evidence")
            # Case IDs are not trusted paths either.
            relative = "evidence/" + task["case_id"] + "/" + entry["path"]
            dst = contained(out, relative)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
            if hashlib.sha256(dst.read_bytes()).hexdigest() != digest:
                raise ValueError("Discovery copy failed integrity check")
            mapping.append({"case_id": task["case_id"], "source_id": key,
                            "path": relative, "sha256": digest})
    for name in ("discovery-packet.json", "discovery-A.json", "discovery-B.json"):
        shutil.copyfile(source / name, out / name)
    save(out / "evidence-map.json", {"packet_sha256": claimed, "sources": mapping,
         "phase": "DISCOVERY_ONLY", "claims_released": False, "reviews_filled": 0})
    (out / "README.md").write_text(
        "Discovery review handoff\n\nGive the packet and form A/B to two independent human reviewers separately. "
        "Use evidence-map.json for the local copies. Only source, manifests and artifacts are included. "
        "Inspect without executing project code on the host. Collect both discovery submissions before "
        "releasing the original, separate claim packet. Reviewers supply their own identities, attestations, "
        "notes and source IDs; this script supplies no decisions.\n")
    print(json.dumps({"evidence_files": len(mapping), "reviews_filled": 0, "packet_sha256": claimed}))


if __name__ == "__main__":
    main()
