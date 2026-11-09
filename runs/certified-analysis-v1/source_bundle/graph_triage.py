"""Backward-compatibility shim. Aliased to sbom_recovery.metrics.graph_triage."""
import sys
from sbom_recovery.metrics import graph_triage
sys.modules[__name__] = graph_triage
