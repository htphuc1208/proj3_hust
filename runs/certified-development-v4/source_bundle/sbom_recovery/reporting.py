"""Backward-compatibility shim. Aliased to sbom_recovery.metrics.reporting."""
import sys
from sbom_recovery.metrics import reporting
sys.modules[__name__] = reporting
