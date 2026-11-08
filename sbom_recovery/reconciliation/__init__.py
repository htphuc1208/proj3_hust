"""Subpackage sbom_recovery.reconciliation."""
import sys
from . import reconciliation
reconciliation.__path__ = [__path__[0]]
sys.modules[__name__] = reconciliation
