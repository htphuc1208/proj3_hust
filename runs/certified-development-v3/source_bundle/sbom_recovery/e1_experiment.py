"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.e1_experiment."""
import sys
from sbom_recovery.campaign import e1_experiment
sys.modules[__name__] = e1_experiment
