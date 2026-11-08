"""Subpackage sbom_recovery.campaign."""
import sys
from . import campaign
campaign.__path__ = [__path__[0]]
sys.modules[__name__] = campaign
