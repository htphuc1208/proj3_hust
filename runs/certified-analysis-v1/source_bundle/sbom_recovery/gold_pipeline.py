"""Backward-compatibility shim. Aliased to sbom_recovery.gold.gold_pipeline."""
import sys
from sbom_recovery.gold import gold_pipeline
sys.modules[__name__] = gold_pipeline
