"""Backward-compatibility shim. Aliased to sbom_recovery.campaign.capture_worker."""
import sys
from sbom_recovery.campaign import capture_worker
sys.modules[__name__] = capture_worker

if __name__ == "__main__":
    capture_worker.main()

