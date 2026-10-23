"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.container_runner."""
import sys
from sbom_recovery.campaign import container_runner
sys.modules[__name__] = container_runner
