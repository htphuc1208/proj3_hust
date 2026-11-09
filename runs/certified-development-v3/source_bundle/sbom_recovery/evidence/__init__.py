"""Subpackage sbom_recovery.evidence."""
import sys
from . import evidence
evidence.__path__ = [__path__[0]]
sys.modules[__name__] = evidence
