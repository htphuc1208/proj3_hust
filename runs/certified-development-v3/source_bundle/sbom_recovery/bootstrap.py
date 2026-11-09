"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.bootstrap."""
import sys
from sbom_recovery.campaign import bootstrap
sys.modules[__name__] = bootstrap
