"""Otacon — domain impersonation detector.

A modular, strictly typed toolkit for detecting typosquatting, homoglyph attacks,
and combosquatting.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from .core.exceptions import (
    ConfigurationError,
    DNSResolutionError,
    HTTPProbeError,
    OtaconError,
    PermutationError,
    ReportExportError,
    ResolutionError,
    ScoringError,
    SecurityError,
    SSRFBlockedError,
    TLSProbeError,
    ValidationError,
    WhoisError,
)
from .core.models import (
    DomainResult,
    NetworkSignals,
    Permutation,
    RiskAssessment,
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
    "ConfigurationError",
    "DNSResolutionError",
    "DomainResult",
    "HTTPProbeError",
    "NetworkSignals",
    "OtaconError",
    "Permutation",
    "PermutationError",
    "PermutationType",
    "ReportExportError",
    "ResolutionError",
    "RiskAssessment",
    "RiskLevel",
    "SSRFBlockedError",
    "ScanReport",
    "ScoringError",
    "SecurityError",
    "TLSProbeError",
    "ValidationError",
    "WhoisError",
    "__version__",
    "count_fresh",
    "generate",
    "run_scan",
    "score",
]
