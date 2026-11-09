"""Backward-compatibility shim. Aliased to sbom_recovery.agents.worker."""
import sys
from sbom_recovery.agents import worker
sys.modules[__name__] = worker
if __name__ == "__main__":
    worker.main()

