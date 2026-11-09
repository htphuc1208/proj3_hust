"""Backward-compatibility shim. Aliased to sbom_recovery.gold.gold_review."""
import sys
from sbom_recovery.gold import gold_review
sys.modules[__name__] = gold_review
