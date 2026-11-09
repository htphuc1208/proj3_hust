"""Backward-compatibility shim. Aliased to sbom_recovery.gold.proof."""
import sys
from sbom_recovery.gold import proof
sys.modules[__name__] = proof
