"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.fresh_selection."""
import sys
from sbom_recovery.campaign import fresh_selection
sys.modules[__name__] = fresh_selection
