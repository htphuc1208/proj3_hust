#!/usr/bin/env python3
"""Container entrypoint exposing only frozen observation, context and evidence."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from registry_provider import FrozenRegistryEvidenceProvider
from repair_agent import RepairSession, scripted_policy


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("input", "evidence", "context", "out"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    session = RepairSession(json.loads(Path(args.input).read_text()), FrozenRegistryEvidenceProvider(Path(args.evidence)),
                            json.loads(Path(args.context).read_text()))
    result = scripted_policy(session)
    Path(args.out).write_text(json.dumps(result, indent=2, sort_keys=True,
        default=lambda value: sorted(value) if isinstance(value, set) else str(value)) + "\n")
