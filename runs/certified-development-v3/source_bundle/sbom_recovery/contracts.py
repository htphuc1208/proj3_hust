"""Backward-compatibility shim. Aliased to sbom_recovery.core.contracts."""
import sys
from sbom_recovery.core import contracts
sys.modules[__name__] = contracts
