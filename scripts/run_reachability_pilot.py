#!/usr/bin/env python3
"""Prepare, execute or independently re-assess the controlled Level 2/3 pilot."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sbom_recovery.reachability_pilot import prepare, run, verify
from sbom_recovery.storage import save


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "run", "verify"])
    parser.add_argument("--out", required=True)
    parser.add_argument("--config", default=str(ROOT / "configs/reachability-pilot-v1.json"))
    args = parser.parse_args()
    if args.command == "prepare":
        result = prepare(args.out, args.config)
        print("PREPARED", len(result["build_files"]), "frozen build files")
    elif args.command == "run":
        result = run(args.out)
        print(json.dumps({k: v for k, v in result.items() if k != "cases"}, indent=2))
    else:
        result = verify(args.out)
        save(Path(args.out) / "verification.json", result)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
