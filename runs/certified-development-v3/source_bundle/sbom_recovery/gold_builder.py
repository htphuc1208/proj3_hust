"""Backward-compatibility shim. Aliased to sbom_recovery.gold.gold_builder."""
import sys
from sbom_recovery.gold import gold_builder
sys.modules[__name__] = gold_builder
