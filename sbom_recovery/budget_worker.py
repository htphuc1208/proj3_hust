"""Backward-compatibility shim. Aliased to sbom_recovery.agents.budget_worker."""
import sys
from sbom_recovery.agents import budget_worker
sys.modules[__name__] = budget_worker
