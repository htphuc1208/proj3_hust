"""Backward-compatibility shim. Aliased to sbom_recovery.core.formats."""
import sys
from sbom_recovery.core import formats
sys.modules[__name__] = formats
