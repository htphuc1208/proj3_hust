"""Backward-compatibility shim. Aliased to sbom_recovery.metrics.security."""
import sys
from sbom_recovery.metrics import security
sys.modules[__name__] = security
