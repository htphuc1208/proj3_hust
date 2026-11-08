"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.budget_recover."""
import sys
from sbom_recovery.campaign import budget_recover
sys.modules[__name__] = budget_recover
