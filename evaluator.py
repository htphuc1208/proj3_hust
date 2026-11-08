"""Backward-compatibility shim. Aliased to sbom_recovery.metrics.evaluator."""
import sys
from sbom_recovery.metrics import evaluator
sys.modules[__name__] = evaluator
