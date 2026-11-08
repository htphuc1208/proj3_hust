#!/usr/bin/env python3
"""Compatibility entrypoint for information ablation. Old nominal factorial results are legacy."""
import argparse
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.run_information_ablation import run

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--base-snapshot", type=Path, required=True)
    p.add_argument("--replay", type=Path)
    a = p.parse_args()
    run(a.out, a.base_snapshot, a.replay)
