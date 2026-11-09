"""Backward-compatibility shim. Aliased to sbom_recovery.bridge.workbench."""
import sys
from sbom_recovery.bridge import workbench
sys.modules[__name__] = workbench
