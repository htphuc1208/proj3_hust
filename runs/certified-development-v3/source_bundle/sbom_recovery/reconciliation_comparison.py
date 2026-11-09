"""Backward-compatibility shim. Aliased to sbom_recovery.reconciliation.reconciliation_comparison."""
import sys
from sbom_recovery.reconciliation import reconciliation_comparison
sys.modules[__name__] = reconciliation_comparison
