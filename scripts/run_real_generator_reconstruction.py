#!/usr/bin/env python3
"""Corrected real-generator entrypoint. Historical reports are never overwritten."""
import argparse
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research_core import normalize_sbom
from scripts.run_scientific_validation import run


def parse_and_normalize_syft_sbom(raw_syft, root_name=None):
    document, audit = normalize_sbom(raw_syft, root_name, bootstrap=("pip", "setuptools"))
    return document, [r for r in audit["components"] if not r["retained_for_inference"]]


def parse_and_normalize_cyclonedx_sbom(raw_cdx, root_name=None):
    return normalize_sbom(raw_cdx, root_name, bootstrap=("pip", "setuptools"))[0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--replay", type=Path)
    args = parser.parse_args()
    run(args.out, args.replay)
