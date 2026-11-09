"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.budget_job."""
import sys
from sbom_recovery.campaign import budget_job
sys.modules[__name__] = budget_job

if __name__ == "__main__":
    budget_job.main()

