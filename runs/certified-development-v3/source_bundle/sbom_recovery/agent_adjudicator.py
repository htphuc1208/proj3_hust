"""Backward-compatibility shim. Aliased to sbom_recovery.agents.agent_adjudicator."""
import sys
from sbom_recovery.agents import agent_adjudicator
sys.modules[__name__] = agent_adjudicator
