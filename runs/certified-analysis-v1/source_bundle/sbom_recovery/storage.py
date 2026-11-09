"""Backward-compatibility shim. Aliased to sbom_recovery.evidence.storage."""
import sys
from sbom_recovery.evidence import storage
sys.modules[__name__] = storage
