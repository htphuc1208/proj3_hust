"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.budget_sources."""
import sys
from sbom_recovery.campaign import budget_sources
sys.modules[__name__] = budget_sources
