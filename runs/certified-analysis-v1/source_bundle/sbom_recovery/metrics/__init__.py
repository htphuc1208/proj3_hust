"""Subpackage sbom_recovery.metrics."""
import sys
from . import metrics
metrics.__path__ = [__path__[0]]
sys.modules[__name__] = metrics
