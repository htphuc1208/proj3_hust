"""Backward-compatibility shim. Aliased to sbom_recovery.gold.references."""
import sys
from sbom_recovery.gold import references
sys.modules[__name__] = references
