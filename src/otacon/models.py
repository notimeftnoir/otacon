"""Data models compatibility shim for otacon v2.0."""

from __future__ import annotations

from .core.models import (
    DomainResult,
    Permutation,
    ScanReport,
)
from .core.types import PermutationType, RiskLevel

__all__ = [
    "DomainResult",
    "Permutation",
    "PermutationType",
    "RiskLevel",
    "ScanReport",
]
