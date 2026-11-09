"""Backward-compatibility shim. Aliased to sbom_recovery.metrics.selective_gate."""
import sys
from sbom_recovery.metrics import selective_gate
sys.modules[__name__] = selective_gate
