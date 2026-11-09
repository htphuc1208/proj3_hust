"""Backward-compatibility shim. Aliased to sbom_recovery.agents.llm."""
import sys
from sbom_recovery.agents import llm
sys.modules[__name__] = llm
