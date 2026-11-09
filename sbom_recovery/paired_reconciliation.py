"""Backward-compatibility shim. Aliased to sbom_recovery.reconciliation.paired_reconciliation."""
import sys
from sbom_recovery.reconciliation import paired_reconciliation
sys.modules[__name__] = paired_reconciliation

if __name__ == "__main__":
    paired_reconciliation.main()

