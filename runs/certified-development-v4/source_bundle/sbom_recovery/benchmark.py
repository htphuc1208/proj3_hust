"""Backward-compatibility shim. Aliased to sbom_recovery.baselines.benchmark."""
import sys
from sbom_recovery.baselines import benchmark
sys.modules[__name__] = benchmark

if __name__ == "__main__":
    benchmark.main()

