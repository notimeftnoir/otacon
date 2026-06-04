"""Risk scoring engine."""
from __future__ import annotations

from .models import DomainResult, PermutationType
from .theme import RiskLevel

_KIND_BASE: dict[PermutationType, int] = {
    PermutationType.HOMOGLYPH: 25,
    PermutationType.TYPO: 18,
    PermutationType.BITSQUAT: 15,
    PermutationType.HYPHEN: 12,
    PermutationType.COMBO: 20,
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
    if result.redirects_to and target and target.lower() in result.redirects_to.lower():
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

    if result.redirects_to:
        points += 5
        reasons.append("redirects elsewhere (+5)")

    result.risk_score = min(points, 100)
    result.risk_level = RiskLevel.from_score(result.risk_score)
    result.risk_reasons = reasons
    return result


def score_all(results: list[DomainResult], target: str = "") -> list[DomainResult]:
    """Scores the whole list in-place."""
    return [score(r, target) for r in results]
