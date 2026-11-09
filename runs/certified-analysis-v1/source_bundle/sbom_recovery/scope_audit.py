"""Backward-compatibility shim. Aliased to sbom_recovery.metrics.scope_audit."""
import sys
from sbom_recovery.metrics import scope_audit
sys.modules[__name__] = scope_audit
