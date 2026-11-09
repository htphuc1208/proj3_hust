"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.materialized_scope."""
import sys
from sbom_recovery.campaign import materialized_scope
sys.modules[__name__] = materialized_scope
