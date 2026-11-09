"""Backward-compatibility shim. Aliased to sbom_recovery.core.canonical."""
import sys
from sbom_recovery.core import canonical
sys.modules[__name__] = canonical
