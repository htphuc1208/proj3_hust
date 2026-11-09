"""Backward-compatibility shim. Aliased to sbom_recovery.evidence.wheel_acquisition."""
import sys
from sbom_recovery.evidence import wheel_acquisition
sys.modules[__name__] = wheel_acquisition
