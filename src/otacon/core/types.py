"""Core enumeration types and type aliases for Otacon."""

from __future__ import annotations

from enum import Enum

type DomainName = str
type IPAddress = str
type PortNumber = int


class PermutationType(str, Enum):
    """The permutation algorithm that produced a domain variant."""

    TYPO = "typo"
    HOMOGLYPH = "homoglyph"
    COMBO = "combosquat"
    TLD_SWAP = "tld-swap"
    BITSQUAT = "bitsquat"
    HYPHEN = "hyphenation"
    SOUNDSQUAT = "soundsquat"
    SUBDOMAIN = "subdomain"
    VOWEL_SWAP = "vowel-swap"
    PLURAL = "plural"
    IDN = "idn"
    WWW_MERGE = "www-merge"
    CT_LOG = "ct-log"


class ScanPhase(str, Enum):
    """Which stage of a scan is running.

    These are the stages a scan actually has, which is not the same as the
    list of checks it performs: DNS, HTTP, TLS, WHOIS and DNSBL all happen
    together inside one per-domain probe, so they are not stages at all.
    What the operator waits through is building the candidate list,
    discovering more of them from Certificate Transparency, and then checking
    them — and the middle one is a single slow network call that used to
    report nothing while it ran.
    """

    GENERATING = "generating"
    DISCOVERING = "discovering"
    CHECKING = "checking"


class RiskLevel(str, Enum):
    """Risk severity classification for lookalike domain variants."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def style(self) -> str:
        """Rich theme style name corresponding to this risk level."""
        return {
            RiskLevel.SAFE: "ok",
            RiskLevel.LOW: "info",
            RiskLevel.MEDIUM: "warn",
            RiskLevel.HIGH: "danger",
            RiskLevel.CRITICAL: "critical",
        }[self]

    @property
    def icon(self) -> str:
        """Text status glyph representing the density ramp."""
        return {
            RiskLevel.SAFE: "○",
            RiskLevel.LOW: "░",
            RiskLevel.MEDIUM: "▒",
            RiskLevel.HIGH: "▓",
            RiskLevel.CRITICAL: "█",
        }[self]

    @property
    def rank(self) -> int:
        """Numeric rank for severity threshold comparisons (0=safe .. 4=critical)."""
        return {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    @classmethod
    def from_score(cls, score: int) -> RiskLevel:
        """Maps an integer risk score (0-100) to its corresponding RiskLevel."""
        if score >= 80:
            return cls.CRITICAL
        if score >= 60:
            return cls.HIGH
        if score >= 35:
            return cls.MEDIUM
        if score >= 15:
            return cls.LOW
        return cls.SAFE
