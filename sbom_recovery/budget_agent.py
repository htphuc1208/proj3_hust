"""Backward-compatibility shim. Aliased to sbom_recovery.agents.budget_agent."""
import sys
from sbom_recovery.agents import budget_agent
sys.modules[__name__] = budget_agent
