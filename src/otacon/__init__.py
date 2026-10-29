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
from .core.models import DomainResult, Permutation, ScanOptions, ScanReport
from .core.types import PermutationType, RiskLevel
from .engine.scanner import run_scan
from .permutations.generator import generate
from .scoring.engine import count_fresh, score

try:
    __version__ = version("otacon")
except PackageNotFoundError:
    # Only reached from a source tree with no installed metadata. Keep it in
    # step with pyproject.toml, or that tree reports the previous release.
    __version__ = "3.0.0"

__all__ = [
    "ConfigurationError",
    "DNSResolutionError",
    "DomainResult",
    "HTTPProbeError",
    "OtaconError",
    "Permutation",
    "PermutationError",
    "PermutationType",
    "ReportExportError",
    "ResolutionError",
    "RiskLevel",
    "SSRFBlockedError",
    "ScanOptions",
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
