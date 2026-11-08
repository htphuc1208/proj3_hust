"""Backward-compatibility shim. Aliased to sbom_recovery.evidence.registry_provider."""
import sys
from sbom_recovery.evidence import registry_provider
sys.modules[__name__] = registry_provider
