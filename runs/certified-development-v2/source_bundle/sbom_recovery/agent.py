"""Backward-compatibility shim. Aliased to sbom_recovery.agents.agent."""
import sys
from sbom_recovery.agents import agent
sys.modules[__name__] = agent
