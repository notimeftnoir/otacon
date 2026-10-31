"""Core domain models, types, and exceptions for Otacon."""

from __future__ import annotations

from .exceptions import (
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
from .models import DomainResult, Permutation, ScanOptions, ScanReport
from .schemas import (
    DomainResultSchema,
    PermutationSchema,
    ScanOptionsSchema,
    ScanReportSchema,
)
from .types import PermutationType, RiskLevel

__all__ = [
    "ConfigurationError",
    "DNSResolutionError",
    "DomainResult",
    "DomainResultSchema",
    "HTTPProbeError",
    "OtaconError",
    "Permutation",
    "PermutationError",
    "PermutationSchema",
    "PermutationType",
    "ReportExportError",
    "ResolutionError",
    "RiskLevel",
    "SSRFBlockedError",
    "ScanOptions",
    "ScanOptionsSchema",
    "ScanReport",
    "ScanReportSchema",
    "ScoringError",
    "SecurityError",
    "TLSProbeError",
    "ValidationError",
    "WhoisError",
]
