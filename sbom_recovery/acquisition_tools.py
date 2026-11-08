"""Backward-compatibility shim. Aliased to sbom_recovery.agents.acquisition_tools."""
import sys
from sbom_recovery.agents import acquisition_tools
sys.modules[__name__] = acquisition_tools
