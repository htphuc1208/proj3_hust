"""Backward-compatibility shim. Aliased to sbom_recovery.reconciliation.native_graph."""
import sys
from sbom_recovery.reconciliation import native_graph
sys.modules[__name__] = native_graph
