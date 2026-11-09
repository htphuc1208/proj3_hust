"""Backward-compatibility shim. Aliased to sbom_recovery.metrics.calibration."""
import sys
from sbom_recovery.metrics import calibration
sys.modules[__name__] = calibration
