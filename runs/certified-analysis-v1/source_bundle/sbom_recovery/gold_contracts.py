"""Backward-compatibility shim. Aliased to sbom_recovery.gold.gold_contracts."""
import sys
from sbom_recovery.gold import gold_contracts
sys.modules[__name__] = gold_contracts
