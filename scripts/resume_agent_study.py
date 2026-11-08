#!/usr/bin/env python3
"""Restart a stopped study from its own frozen controller and exact saved plan."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run",required=True)
    p.add_argument("--foreground",action="store_true")
    args=p.parse_args()
    run=Path(args.run).resolve()
    plan=json.loads((run/"plan.json").read_text())
    state=json.loads((run/"state.json").read_text()) if (run/"state.json").exists() else {}
    pid=state.get("pid")
    if pid:
        try:
            command=Path(f"/proc/{pid}/cmdline").read_bytes()
        except FileNotFoundError:
            command=b""
        if str(run).encode() in command and b"run_agent_study.py" in command:
            raise RuntimeError("This study controller is already running; inspect --status")
    bundle=run/"source_bundle"
    manifest=json.loads((bundle/"source_manifest.json").read_text())
    for name,expected in manifest["files"].items():
        if hashlib.sha256((bundle/name).read_bytes()).hexdigest()!=expected:
            raise ValueError("Frozen source mismatch: "+name)
    command=[sys.executable,"-B",str(bundle/"scripts/run_agent_study.py"),
        "--cohort",plan["cohort"],"--captures",plan["captures"],"--snapshot",plan["snapshot"],
        "--out",str(run),"--workers",str(plan["workers"]),
        "--development-runs",*plan["development_runs"],"--ask-key"]
    if not args.foreground:command.append("--background")
    os.execv(sys.executable,command)


if __name__=="__main__":main()
