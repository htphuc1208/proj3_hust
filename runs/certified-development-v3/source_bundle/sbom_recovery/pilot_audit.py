"""Backward-compatibility shim. Aliased to sbom_recovery.metrics.pilot_audit."""
import sys
from sbom_recovery.metrics import pilot_audit
sys.modules[__name__] = pilot_audit
