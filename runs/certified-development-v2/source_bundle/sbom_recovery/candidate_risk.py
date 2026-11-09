"""Backward-compatibility shim. Aliased to sbom_recovery.metrics.candidate_risk."""
import sys
from sbom_recovery.metrics import candidate_risk
sys.modules[__name__] = candidate_risk
