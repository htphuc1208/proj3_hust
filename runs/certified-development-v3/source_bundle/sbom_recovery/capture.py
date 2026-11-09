"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.capture."""
import sys
from sbom_recovery.campaign import capture
sys.modules[__name__] = capture
