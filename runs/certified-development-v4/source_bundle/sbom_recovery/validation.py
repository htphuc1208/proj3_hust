"""Backward-compatibility shim. Aliased to sbom_recovery.metrics.validation."""
import sys
from sbom_recovery.metrics import validation
sys.modules[__name__] = validation
