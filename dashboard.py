"""Backward-compatibility shim. Aliased to sbom_recovery.bridge.dashboard."""
import sys
from sbom_recovery.bridge import dashboard
sys.modules[__name__] = dashboard
