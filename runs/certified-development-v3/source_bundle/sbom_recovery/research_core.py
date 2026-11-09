"""Backward-compatibility shim. Aliased to sbom_recovery.core.research_core."""
import sys
from sbom_recovery.core import research_core
sys.modules[__name__] = research_core
