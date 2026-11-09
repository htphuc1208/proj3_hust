"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.cohort."""
import sys
from sbom_recovery.campaign import cohort
sys.modules[__name__] = cohort
