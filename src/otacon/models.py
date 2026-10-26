"""Data models (Pydantic).

Central structures flowing through the entire pipeline:
permutations -> resolver -> scoring -> reporters.

Pydantic gives us, for free: validation, type safety, and JSON
serialization (report export with no extra code).
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from .theme import RiskLevel


class PermutationType(str, Enum):
    """The permutation algorithm that produced a variant.

    Lets reports group/filter results and explains to the user WHY a given
    variant was generated.
    """

    TYPO = "typo"  # typos (omission, insertion, swap)
    HOMOGLYPH = "homoglyph"  # visually identical characters (unicode/ascii)
    COMBO = "combosquat"  # appended words: -login, -secure...
    TLD_SWAP = "tld-swap"  # TLD change: .com -> .net
    BITSQUAT = "bitsquat"  # bit-flip (memory errors)
    HYPHEN = "hyphenation"  # adding/removing a hyphen
    SOUNDSQUAT = "soundsquat"  # phonetic substitution (ph/f, c/k, s/z …)
    SUBDOMAIN = "subdomain"  # original domain as subdomain of spoof registrar
    VOWEL_SWAP = "vowel-swap"  # replace each vowel with every other vowel
    PLURAL = "plural"  # plural / singular suffix variation
    IDN = "idn"  # ACE/punycode encoding of unicode homoglyph
    WWW_MERGE = "www-merge"  # 'www' subdomain merged into the domain (dot omission)
    DIACRITIC = "diacritic"  # diacritic added or dropped: allegro <-> allęgro, żabka <-> zabka


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
    has_mx: bool = False  # readiness for email phishing
    mx_records: list[str] = Field(default_factory=list)
    # Nameservers, fetched for registered variants only: parking providers
    # give themselves away here even when the page title does not.
    ns_records: list[str] = Field(default_factory=list)
    has_ssl: bool = False  # active certificate (port 443)
    ssl_issuer: str | None = None  # CN of the cert issuer (e.g. "Let's Encrypt")
    ssl_cert_age_days: int | None = None  # days since cert notBefore — fresh = phishing signal
    ssl_san_matches: bool | None = None  # True when SAN covers the probed host
    http_status: int | None = None  # HTTP(S) response
    server_header: str | None = None
    redirects_to: str | None = None
    # Threat-intel feeds listing this domain or a subdomain of it (see intel.py).
    intel_sources: list[str] = Field(default_factory=list)
    # No DNS answer at all, even after retries: registration is unknown, which
    # is not the same as "not registered".
    dns_inconclusive: bool = False

    # Page title — parsed from HTML body on 2xx responses; None when absent/failed.
    page_title: str | None = None
    title_similarity: float | None = None

    # WHOIS — filled for registered domains only; None when lookup fails.
    created_at: datetime | None = None
    age_days: int | None = None

    # Scoring result — filled in by scoring.py.
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE
    risk_reasons: list[str] = Field(default_factory=list)
    is_likely_defensive: bool = False
    is_parked: bool = False

    @property
    def is_registered(self) -> bool:
        """Whether the variant looks actively registered / in use."""
        return self.resolves or self.has_mx or self.has_ssl


class Discovery(BaseModel):
    """A host carrying the brand that turned up outside the permutation set
    (threat-intel feeds, certificate logs). Reported, never probed."""

    host: str
    sources: list[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    """Complete scan report — root of the JSON export object."""

    target: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    total_permutations: int = 0
    results: list[DomainResult] = Field(default_factory=list)
    # True when the local resolver answered a random nonexistent domain —
    # NXDOMAIN hijacking. Affected answers were discarded (see Resolver).
    dns_hijack_detected: bool = False
    # Brand-bearing hosts found outside the permutations (see Discovery).
    discovered: list[Discovery] = Field(default_factory=list)

    @property
    def registered(self) -> list[DomainResult]:
        """Only variants that actually exist (worth attention)."""
        return [r for r in self.results if r.is_registered]

    @property
    def inconclusive(self) -> list[DomainResult]:
        """Variants whose DNS never answered — possibly registered, unverified."""
        return [r for r in self.results if r.dns_inconclusive]

    @property
    def threats(self) -> list[DomainResult]:
        """Elevated-risk variants, sorted descending by score."""
        flagged = [r for r in self.results if r.risk_level != RiskLevel.SAFE]
        return sorted(flagged, key=lambda r: r.risk_score, reverse=True)
