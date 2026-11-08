"""Backward-compatibility shim. Aliased to sbom_recovery.bridge.experiment."""
import sys
from sbom_recovery.bridge import experiment
sys.modules[__name__] = experiment

if __name__ == "__main__":
    experiment.main()
