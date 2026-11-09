"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.recover."""
import sys
from sbom_recovery.campaign import recover
sys.modules[__name__] = recover
