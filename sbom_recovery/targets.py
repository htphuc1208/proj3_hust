"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.targets."""
import sys
from sbom_recovery.campaign import targets
sys.modules[__name__] = targets
