"""Domain exception hierarchy for Otacon.

Enforces structured error handling across network, validation, and permutation pipelines.
"""

from __future__ import annotations


class OtaconError(Exception):
    """Base exception for all domain-specific errors in Otacon."""


class ConfigurationError(OtaconError):
    """Raised when runtime options, CLI arguments, or heuristic weights are invalid."""


class ValidationError(OtaconError):
    """Raised when domain names, IP addresses, or file paths fail RFC/security validation."""


class PermutationError(OtaconError):
    """Raised when domain permutation generation or IDNA encoding encounters an error."""


class ResolutionError(OtaconError):
    """Raised when a network transport or lookup failure occurs."""


class DNSResolutionError(ResolutionError):
    """Raised when DNS resolution fails unrecoverably."""


class TLSProbeError(ResolutionError):
    """Raised when TLS socket handshake or certificate inspection fails."""


class HTTPProbeError(ResolutionError):
    """Raised during HTTP/HTTPS probe or content streaming."""


class WhoisError(ResolutionError):
    """Raised when RDAP or WHOIS querying fails."""


class SecurityError(OtaconError):
    """Raised when a security boundary is breached."""


class SSRFBlockedError(SecurityError):
    """Raised when an outbound connection attempts to reach an unvetted/internal IP address."""


class ScoringError(OtaconError):
    """Raised when risk evaluation calculations fail."""


class ReportExportError(OtaconError):
    """Raised when saving or rendering scan reports encounters a failure."""
