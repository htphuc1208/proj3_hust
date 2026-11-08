"""Backward-compatibility shim. Aliased to sbom_recovery.reconciliation.reachability_worker."""
import sys
from sbom_recovery.reconciliation import reachability_worker
sys.modules[__name__] = reachability_worker
