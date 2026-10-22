"""Backward-compatibility shim. Aliased to sbom_recovery.evidence.public_evidence."""
import sys
from sbom_recovery.evidence import public_evidence
sys.modules[__name__] = public_evidence
