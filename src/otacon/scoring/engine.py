"""Risk scoring engine computing transparent heuristic threat scores."""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..core.models import DomainResult
from ..core.types import RiskLevel
from .classifiers import is_defensive, is_parked, is_sinkhole
from .config import ScoringWeights

AGE_FRESH_DAYS = 7
AGE_NEW_DAYS = 30
AGE_RECENT_DAYS = 90


def get_age_fresh_days() -> int:
    """Gets the active AGE_FRESH_DAYS threshold, tracking runtime monkeypatching."""
    import sys

    scoring_mod = sys.modules.get("otacon.scoring")
    if scoring_mod is not None:
        val = getattr(scoring_mod, "AGE_FRESH_DAYS", None)
        if val is not None and val != 7:
            return int(val)

    engine_mod = sys.modules.get("otacon.scoring.engine")
    if engine_mod is not None:
        val = getattr(engine_mod, "AGE_FRESH_DAYS", None)
        if val is not None and val != 7:
            return int(val)

    return AGE_FRESH_DAYS


def get_age_new_days() -> int:
    """Gets the active AGE_NEW_DAYS threshold, tracking runtime monkeypatching."""
    import sys

    scoring_mod = sys.modules.get("otacon.scoring")
    if scoring_mod is not None:
        val = getattr(scoring_mod, "AGE_NEW_DAYS", None)
        if val is not None and val != 30:
            return int(val)
    return AGE_NEW_DAYS


def count_fresh(results: Iterable[DomainResult]) -> int:
    """Counts registered results whose WHOIS age is under AGE_FRESH_DAYS."""
    fresh_limit = get_age_fresh_days()
    return sum(1 for r in results if r.age_days is not None and r.age_days < fresh_limit)


def _title_similarity(t1: str, t2: str) -> float:
    """Computes Jaccard word similarity between two titles."""
    w1 = set(re.findall(r"\w+", t1.lower()))
    w2 = set(re.findall(r"\w+", t2.lower()))
    if not w1 or not w2:
        return 0.0
    return len(w1 & w2) / len(w1 | w2)


def _technique_points(result: DomainResult, reasons: list[str], weights: ScoringWeights) -> int:
    base = weights.kind_base.get(result.kind, 10)
    reasons.append(f"technique: {result.kind.value} (+{base})")
    return base


def _network_points(
    result: DomainResult, reasons: list[str], weights: ScoringWeights, parked: bool
) -> int:
    if parked:
        reasons.append("detected as parked domain (HTTP/DNS signals ignored)")
        return 0
    points = 0
    if result.resolves:
        points += weights.points_resolves
        reasons.append(f"resolves to an IP (+{weights.points_resolves})")
    status = result.http_status
    if status is None:
        return points
    if 200 <= status < 300:
        points += weights.points_http_2xx
        reasons.append(f"responds HTTP {status} — active site (+{weights.points_http_2xx})")
    elif 300 <= status < 400:
        points += weights.points_http_3xx
        reasons.append(f"responds HTTP {status} — redirect (+{weights.points_http_3xx})")
    elif 400 <= status < 500:
        points += weights.points_http_4xx
        reasons.append(
            f"responds HTTP {status} — registered, no content (+{weights.points_http_4xx})"
        )
    else:
        points += weights.points_http_5xx
        reasons.append(f"responds HTTP {status} — server error (+{weights.points_http_5xx})")
    return points


def _tls_points(result: DomainResult, reasons: list[str], weights: ScoringWeights) -> int:
    if not result.has_ssl:
        return 0
    points = weights.points_ssl
    reasons.append(f"active SSL certificate (+{weights.points_ssl})")
    if result.ssl_cert_age_days is not None and 0 <= result.ssl_cert_age_days < AGE_FRESH_DAYS:
        points += weights.points_ssl_fresh
        reasons.append(
            f"SSL certificate issued {result.ssl_cert_age_days} days ago — fresh "
            f"(+{weights.points_ssl_fresh})"
        )
    if result.ssl_san_matches is False:
        points += weights.points_ssl_san_mismatch
        reasons.append(
            f"SSL cert SAN does not cover this host (+{weights.points_ssl_san_mismatch})"
        )
    return points


def _redirect_points(result: DomainResult, reasons: list[str], weights: ScoringWeights) -> int:
    if not result.redirects_to:
        return 0
    if result.http_status is not None and 200 <= result.http_status < 400:
        return 0
    reasons.append(f"redirects elsewhere (+{weights.points_redirect})")
    return weights.points_redirect


def _age_points(result: DomainResult, reasons: list[str], weights: ScoringWeights) -> int:
    age = result.age_days
    if age is None:
        return 0
    fresh_limit = get_age_fresh_days()
    new_limit = get_age_new_days()
    if age < fresh_limit:
        reasons.append(f"registered {age} days ago (+{weights.points_age_fresh})")
        return weights.points_age_fresh
    if age < new_limit:
        reasons.append(f"registered {age} days ago (+{weights.points_age_new})")
        return weights.points_age_new
    if age < AGE_RECENT_DAYS:
        reasons.append(f"registered {age} days ago (+{weights.points_age_recent})")
        return weights.points_age_recent
    return 0


def _title_points(
    result: DomainResult,
    reasons: list[str],
    weights: ScoringWeights,
    target_title: str | None = None,
) -> tuple[int, float | None]:
    if not target_title or not result.page_title:
        return 0, None
    sim = _title_similarity(target_title, result.page_title)
    rounded_sim = round(sim, 2)
    if sim >= 0.5:
        points = weights.points_cloned_title
        reasons.append(
            "cloned or highly similar page title to target "
            f"(similarity: {rounded_sim:.2f}) (+{points})"
        )
        return points, rounded_sim
    return 0, rounded_sim


def score(
    result: DomainResult,
    target: str = "",
    weights: ScoringWeights | None = None,
    target_title: str | None = None,
) -> DomainResult:
    """Computes risk_score, risk_level, reasons, and classification flags immutably."""
    if not result.is_registered:
        return result.model_copy(
            update={
                "risk_score": 0,
                "risk_level": RiskLevel.SAFE,
                "risk_reasons": [],
            }
        )

    if weights is None:
        weights = ScoringWeights()

    sinkhole = is_sinkhole(result)
    parked = is_parked(result) if not sinkhole else False
    defensive = is_defensive(result, target)

    reasons: list[str] = []
    points = _technique_points(result, reasons, weights)
    points += _network_points(result, reasons, weights, parked)
    if result.has_mx:
        points += weights.points_mx
        reasons.append(f"has an MX record — ready for email phishing (+{weights.points_mx})")
    points += _tls_points(result, reasons, weights)
    points += _redirect_points(result, reasons, weights)
    points += _age_points(result, reasons, weights)
    title_pts, title_sim = _title_points(result, reasons, weights, target_title)
    points += title_pts

    if result.favicon_matches_target:
        points += weights.points_cloned_favicon
        reasons.append(
            f"favicon matches target — cloned visual brand (+{weights.points_cloned_favicon})"
        )

    if result.has_login_form and not parked:
        points += weights.points_login_form
        reasons.append(f"login form / credential input detected (+{weights.points_login_form})")

    if result.has_mx and result.is_mail_spoofable and not parked:
        points += weights.points_mail_spoofable
        pol = result.dmarc_policy or "none"
        reasons.append(
            f"permissive/missing DMARC (p={pol}) — email spoofing vector "
            f"(+{weights.points_mail_spoofable})"
        )

    if result.dnsbl_listed:
        points += weights.points_dnsbl
        source = result.dnsbl_source or "Spamhaus DBL"
        reasons.append(f"listed on {source} — active threat (+{weights.points_dnsbl})")

    final_score = min(points, 100)
    final_level = RiskLevel.from_score(final_score)

    if sinkhole:
        final_score = 0
        final_level = RiskLevel.SAFE
        reasons.append("sinkhole / law enforcement seizure detected (threat neutralized)")
    elif defensive:
        final_score = 0
        final_level = RiskLevel.SAFE
        reasons.append("detected as a defensive registration redirecting to target (risk cleared)")

    return result.model_copy(
        update={
            "risk_score": final_score,
            "risk_level": final_level,
            "risk_reasons": reasons,
            "is_sinkhole": sinkhole,
            "is_parked": parked,
            "is_likely_defensive": defensive,
            "title_similarity": title_sim,
        }
    )


__all__ = [
    "AGE_FRESH_DAYS",
    "AGE_NEW_DAYS",
    "AGE_RECENT_DAYS",
    "ScoringWeights",
    "_age_points",
    "_network_points",
    "_redirect_points",
    "_technique_points",
    "_title_points",
    "_title_similarity",
    "_tls_points",
    "count_fresh",
    "get_age_fresh_days",
    "get_age_new_days",
    "score",
]
