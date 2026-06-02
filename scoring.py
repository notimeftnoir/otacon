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

from .models import DomainResult, PermutationType
from .theme import RiskLevel

# Base "dangerousness" of a technique — how easily a variant fools the eye.
_KIND_BASE: dict[PermutationType, int] = {
    PermutationType.HOMOGLYPH: 25,   # looks identical — most dangerous
    PermutationType.TYPO: 18,
    PermutationType.BITSQUAT: 15,
    PermutationType.HYPHEN: 12,
    PermutationType.COMBO: 20,       # -login etc. = overtly phishing
    PermutationType.TLD_SWAP: 10,
}


def score(result: DomainResult) -> DomainResult:
    """Computes risk_score, risk_level and reasons. Mutates and returns the object."""
    points = 0
    reasons: list[str] = []

    # Unregistered variants = no real threat (for now).
    if not result.is_registered:
        result.risk_score = 0
        result.risk_level = RiskLevel.SAFE
        result.risk_reasons = []
        return result

    # Base from the permutation type.
    base = _KIND_BASE.get(result.kind, 10)
    points += base
    reasons.append(f"technique: {result.kind.value} (+{base})")

    # The domain resolves — someone is actively holding it.
    if result.resolves:
        points += 10
        reasons.append("resolves to an IP (+10)")

    # MX = phishing emails can be sent from it. Strong signal.
    if result.has_mx:
        points += 25
        reasons.append("has an MX record — ready for email phishing (+25)")

    # SSL = someone set up a certificate = serious infrastructure.
    if result.has_ssl:
        points += 15
        reasons.append("active SSL certificate (+15)")

    # Live HTTP response = content is being served.
    if result.http_status is not None:
        if 200 <= result.http_status < 400:
            points += 15
            reasons.append(f"responds HTTP {result.http_status} (+15)")
        else:
            points += 5
            reasons.append(f"HTTP {result.http_status} (+5)")

    # Redirect to the original/another domain — a common trick (parking/cloaking).
    if result.redirects_to:
        points += 5
        reasons.append("redirects elsewhere (+5)")

    result.risk_score = min(points, 100)
    result.risk_level = RiskLevel.from_score(result.risk_score)
    result.risk_reasons = reasons
    return result


def score_all(results: list[DomainResult]) -> list[DomainResult]:
    """Scores the whole list of results in-place."""
    return [score(r) for r in results]
