"""Backward-compatibility shim. Aliased to sbom_recovery.metrics.claim_scorer."""
import sys
from sbom_recovery.metrics import claim_scorer
sys.modules[__name__] = claim_scorer
