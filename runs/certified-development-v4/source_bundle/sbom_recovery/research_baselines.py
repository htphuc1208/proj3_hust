"""Backward-compatibility shim. Aliased to sbom_recovery.baselines.research_baselines."""
import sys
from sbom_recovery.baselines import research_baselines
sys.modules[__name__] = research_baselines
