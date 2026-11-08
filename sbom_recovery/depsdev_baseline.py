"""Backward-compatibility shim. Aliased to sbom_recovery.baselines.depsdev_baseline."""
import sys
from sbom_recovery.baselines import depsdev_baseline
sys.modules[__name__] = depsdev_baseline
