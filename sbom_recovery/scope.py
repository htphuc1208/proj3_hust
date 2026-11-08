"""Backward-compatibility shim. Aliased to sbom_recovery.core.scope."""
import sys
from sbom_recovery.core import scope
sys.modules[__name__] = scope
