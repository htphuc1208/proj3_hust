"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.materialized_worker."""
import sys
from sbom_recovery.campaign import materialized_worker
sys.modules[__name__] = materialized_worker
