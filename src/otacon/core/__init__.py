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
from .models import DomainResult, NetworkSignals, Permutation, RiskAssessment, ScanReport
from .schemas import (
    CTLogEntrySchema,
    DomainResultSchema,
    PermutationSchema,
    ScanReportSchema,
    ScoringWeightsSchema,
    WhoisResultSchema,
)
from .types import DomainName, IPAddress, PermutationType, PortNumber, RiskLevel

__all__ = [
    "CTLogEntrySchema",
    "ConfigurationError",
    "DNSResolutionError",
    "DomainName",
    "DomainResult",
    "DomainResultSchema",
    "HTTPProbeError",
    "IPAddress",
    "NetworkSignals",
    "OtaconError",
    "Permutation",
    "PermutationError",
    "PermutationSchema",
    "PermutationType",
    "PortNumber",
    "ReportExportError",
    "ResolutionError",
    "RiskAssessment",
    "RiskLevel",
    "SSRFBlockedError",
    "ScanReport",
    "ScanReportSchema",
    "ScoringError",
    "ScoringWeightsSchema",
    "SecurityError",
    "TLSProbeError",
    "ValidationError",
    "WhoisError",
    "WhoisResultSchema",
]
