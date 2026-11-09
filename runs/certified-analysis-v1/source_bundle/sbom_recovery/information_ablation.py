"""Backward-compatibility shim. Aliased to sbom_recovery.baselines.information_ablation."""
import sys
from sbom_recovery.baselines import information_ablation
sys.modules[__name__] = information_ablation
