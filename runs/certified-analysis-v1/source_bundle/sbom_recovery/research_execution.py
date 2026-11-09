"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.research_execution."""
import sys
from sbom_recovery.campaign import research_execution
sys.modules[__name__] = research_execution
