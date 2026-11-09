"""Subpackage sbom_recovery.baselines."""
import sys
from . import baselines
baselines.__path__ = [__path__[0]]
sys.modules[__name__] = baselines
