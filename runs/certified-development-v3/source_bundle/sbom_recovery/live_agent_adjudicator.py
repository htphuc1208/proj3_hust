"""Backward-compatibility shim. Aliased to sbom_recovery.agents.live_agent_adjudicator."""
import sys
from sbom_recovery.agents import live_agent_adjudicator
sys.modules[__name__] = live_agent_adjudicator
