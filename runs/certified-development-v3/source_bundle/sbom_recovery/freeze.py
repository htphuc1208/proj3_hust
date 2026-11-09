"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.freeze."""
import sys
from sbom_recovery.campaign import freeze
sys.modules[__name__] = freeze
