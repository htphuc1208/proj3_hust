"""Backward-compatibility shim. Aliased to sbom_recovery.bridge.poc."""
import sys
from sbom_recovery.bridge import poc
sys.modules[__name__] = poc
