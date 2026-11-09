"""Backward-compatibility shim. Aliased to sbom_recovery.reconciliation.reachability_pilot."""
import sys
from sbom_recovery.reconciliation import reachability_pilot
sys.modules[__name__] = reachability_pilot
