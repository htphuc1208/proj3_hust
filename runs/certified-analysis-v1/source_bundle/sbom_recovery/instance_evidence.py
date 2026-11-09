"""Backward-compatibility shim. Aliased to sbom_recovery.evidence.instance_evidence."""
import sys
from sbom_recovery.evidence import instance_evidence
sys.modules[__name__] = instance_evidence
