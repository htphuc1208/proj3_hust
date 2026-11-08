#!/usr/bin/env python3
"""Capture unrestricted cohort with frozen wheels and no time limit."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sbom_recovery.capture import capture_cohort

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort', default='runs/unrestricted-cohort-selection-v2/cohort.json')
    parser.add_argument('--out', default='runs/unrestricted-builds-v2')
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--limit', type=int, default=None)
    args = parser.parse_args()

    capture_cohort(args.cohort, args.out, limit=args.limit, workers=args.workers, source=True)
    print(f"Capture completed. Output at {args.out}")

if __name__ == '__main__':
    main()
