"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.budget_isolation."""
import sys
from sbom_recovery.campaign import budget_isolation
sys.modules[__name__] = budget_isolation
