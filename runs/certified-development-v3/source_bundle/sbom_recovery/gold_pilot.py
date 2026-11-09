"""Backward-compatibility shim. Aliased to sbom_recovery.gold.gold_pilot."""
import sys
from sbom_recovery.gold import gold_pilot
sys.modules[__name__] = gold_pilot
