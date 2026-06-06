"""Risk scoring engine.

Each collected signal adds points to a 0-100 score. The logic follows the
real-world hierarchy of phishing threat:

  - mere registration of a fake domain = weak signal (a company may own it)
  - MX = the domain is READY for email phishing (serious signal)
  - SSL + live HTTP = active infrastructure (attack in progress?)
  - homoglyphs/typos close to the original = higher risk than a distant combosquat

Scoring is deliberately simple and transparent (explicit rules instead of ML) —
a pentester should understand WHY something received a given score.
"""
from __future__ import annotations

from urllib.parse import urlparse

from .models import DomainResult, PermutationType
from .theme import RiskLevel

_KIND_BASE: dict[PermutationType, int] = {
    PermutationType.HOMOGLYPH: 25,
    PermutationType.IDN: 25,
    PermutationType.SUBDOMAIN: 22,
    PermutationType.COMBO: 20,
    PermutationType.TYPO: 18,
    PermutationType.SOUNDSQUAT: 16,
    PermutationType.BITSQUAT: 15,
    PermutationType.HYPHEN: 12,
    PermutationType.VOWEL_SWAP: 14,
    PermutationType.PLURAL: 10,
    PermutationType.TLD_SWAP: 10,
}


def score(result: DomainResult, target: str = "") -> DomainResult:
    """Computes risk_score, risk_level, reasons, and is_likely_defensive. Mutates and returns."""
    if not result.is_registered:
        result.risk_score = 0
        result.risk_level = RiskLevel.SAFE
        result.risk_reasons = []
        return result

    # Defensive-registration detection: redirect points back to the original domain.
    if result.redirects_to and target:
        _host = (urlparse(result.redirects_to).hostname or "").lower().rstrip(".")
        _t = target.lower().strip(".")
        if _host == _t or _host.endswith("." + _t):
            result.is_likely_defensive = True

    points = 0
    reasons: list[str] = []

    base = _KIND_BASE.get(result.kind, 10)
    points += base
    reasons.append(f"technique: {result.kind.value} (+{base})")

    if result.resolves:
        points += 10
        reasons.append("resolves to an IP (+10)")

    if result.has_mx:
        points += 25
        reasons.append("has an MX record — ready for email phishing (+25)")

    if result.has_ssl:
        points += 15
        reasons.append("active SSL certificate (+15)")

    if result.http_status is not None:
        status = result.http_status
        if 200 <= status < 300:
            points += 15
            reasons.append(f"responds HTTP {status} — active site (+15)")
        elif 300 <= status < 400:
            points += 10
            reasons.append(f"responds HTTP {status} — redirect (+10)")
        elif 400 <= status < 500:
            points += 5
            reasons.append(f"responds HTTP {status} — registered, no content (+5)")
        else:
            points += 3
            reasons.append(f"responds HTTP {status} — server error (+3)")

    # Only add redirect bonus when the HTTP status doesn't already capture it
    # (3xx responses are already scored +10 above — adding +5 here would double-count)
    if result.redirects_to and not (
        result.http_status is not None and 300 <= result.http_status < 400
    ):
        points += 5
        reasons.append("redirects elsewhere (+5)")

    if result.age_days is not None:
        if result.age_days < 7:
            points += 20
            reasons.append(f"registered {result.age_days} days ago (+20)")
        elif result.age_days < 30:
            points += 12
            reasons.append(f"registered {result.age_days} days ago (+12)")
        elif result.age_days < 90:
            points += 5
            reasons.append(f"registered {result.age_days} days ago (+5)")

    result.risk_score = min(points, 100)
    result.risk_level = RiskLevel.from_score(result.risk_score)
    result.risk_reasons = reasons
    return result
