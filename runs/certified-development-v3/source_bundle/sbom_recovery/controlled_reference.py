"""Backward-compatibility shim. Aliased to sbom_recovery.gold.controlled_reference."""
import sys
from sbom_recovery.gold import controlled_reference
sys.modules[__name__] = controlled_reference
