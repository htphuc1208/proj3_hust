"""Backward-compatibility shim. Aliased to sbom_recovery.metrics.verifier."""
import sys
from sbom_recovery.metrics import verifier
sys.modules[__name__] = verifier
