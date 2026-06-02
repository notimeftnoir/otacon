"""Data models (Pydantic).

Central structures flowing through the entire pipeline:
permutations -> resolver -> scoring -> reporters.

Pydantic gives us, for free: validation, type safety, and JSON
serialization (report export with no extra code).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from .theme import RiskLevel


class PermutationType(str, Enum):
    """The permutation algorithm that produced a variant.

    Lets reports group/filter results and explains to the user WHY a given
    variant was generated.
    """

    TYPO = "typo"                  # typos (omission, insertion, swap)
    HOMOGLYPH = "homoglyph"        # visually identical characters (unicode/ascii)
    COMBO = "combosquat"           # appended words: -login, -secure...
    TLD_SWAP = "tld-swap"          # TLD change: .com -> .net
    BITSQUAT = "bitsquat"          # bit-flip (memory errors)
    HYPHEN = "hyphenation"         # adding/removing a hyphen


class Permutation(BaseModel):
    """A single generated domain variant (before any network check)."""

    domain: str
    kind: PermutationType
    # Short description of the technique — ends up in the report as an explanation.
    note: str = ""


class DomainResult(BaseModel):
    """The result of checking one domain variant against the network."""

    domain: str
    kind: PermutationType
    note: str = ""

    # Signals collected by the resolver. False/empty = not found / error.
    resolves: bool = False
    ip_addresses: list[str] = Field(default_factory=list)
    has_mx: bool = False               # readiness for email phishing
    mx_records: list[str] = Field(default_factory=list)
    has_ssl: bool = False              # active certificate (port 443)
    http_status: int | None = None     # HTTP(S) response
    server_header: str | None = None
    redirects_to: str | None = None

    # Scoring result — filled in by scoring.py.
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE
    risk_reasons: list[str] = Field(default_factory=list)

    @property
    def is_registered(self) -> bool:
        """Whether the variant looks actively registered / in use."""
        return self.resolves or self.has_mx or self.has_ssl


class ScanReport(BaseModel):
    """Complete scan report — root of the JSON export object."""

    target: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_permutations: int = 0
    results: list[DomainResult] = Field(default_factory=list)

    @property
    def registered(self) -> list[DomainResult]:
        """Only variants that actually exist (worth attention)."""
        return [r for r in self.results if r.is_registered]

    @property
    def threats(self) -> list[DomainResult]:
        """Elevated-risk variants, sorted descending by score."""
        flagged = [r for r in self.results if r.risk_level != RiskLevel.SAFE]
        return sorted(flagged, key=lambda r: r.risk_score, reverse=True)
