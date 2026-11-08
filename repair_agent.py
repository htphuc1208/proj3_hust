"""Backward-compatibility shim. Aliased to sbom_recovery.agents.repair_agent."""
import sys
from sbom_recovery.agents import repair_agent
sys.modules[__name__] = repair_agent
