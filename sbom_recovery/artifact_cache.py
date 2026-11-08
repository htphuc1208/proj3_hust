"""Backward-compatibility shim. Aliased to sbom_recovery.evidence.artifact_cache."""
import sys
from sbom_recovery.evidence import artifact_cache
sys.modules[__name__] = artifact_cache
