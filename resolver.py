"""Backward-compatibility shim. Aliased to sbom_recovery.core.resolver."""
import sys
from sbom_recovery.core import resolver
sys.modules[__name__] = resolver
