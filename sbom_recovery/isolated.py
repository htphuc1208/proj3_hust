"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.isolated."""
import sys
from sbom_recovery.campaign import isolated
sys.modules[__name__] = isolated
