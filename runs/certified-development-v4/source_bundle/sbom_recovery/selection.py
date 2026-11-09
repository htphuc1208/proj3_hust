"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.selection."""
import sys
from sbom_recovery.campaign import selection
sys.modules[__name__] = selection
