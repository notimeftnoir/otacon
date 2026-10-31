"""Otacon — domain impersonation detector.

A modular, strictly typed toolkit for detecting typosquatting, homoglyph attacks,
and combosquatting.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from .core.models import (
    DomainResult,
    Permutation,
    ScanReport,
)
from .core.types import PermutationType, RiskLevel
from .engine.scanner import run_scan
from .permutations.generator import generate
from .scoring.engine import count_fresh, score

try:
    __version__ = version("otacon")
except PackageNotFoundError:
    __version__ = "4.0.0"

__all__ = [
    "DomainResult",
    "Permutation",
    "PermutationType",
    "RiskLevel",
    "ScanReport",
    "__version__",
    "count_fresh",
    "generate",
    "run_scan",
    "score",
]
