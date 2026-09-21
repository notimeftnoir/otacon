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

import logging
import re
from collections.abc import Iterable
from typing import Any

from ._validate import parse_redirect
from .models import DomainResult, PermutationType
from .theme import RiskLevel

_log = logging.getLogger("otacon.scoring")


class ScoringWeights:
    """Configurable scoring weights for risk calculation."""

    def __init__(self, overrides: dict[str, Any] | None = None) -> None:
        if overrides is not None and not isinstance(overrides, dict):
            # Lives here (not just at the CLI call site) because this class is
            # what actually assumes a dict — _apply_overrides calls .items() on
            # it. A JSON `null` (None) still means "no overrides" and falls
            # through unchanged, matching the pre-existing `if overrides:` check.
            raise TypeError("overrides must be a dict")
        self.points_resolves = 10
        self.points_http_2xx = 15
        self.points_http_3xx = 10
        self.points_http_4xx = 5
        self.points_http_5xx = 3
        self.points_mx = 25
        self.points_ssl = 15
        self.points_ssl_fresh = 10
        self.points_ssl_san_mismatch = 5
        self.points_redirect = 5
        self.points_age_fresh = 20
        self.points_age_new = 12
        self.points_age_recent = 5
        self.points_cloned_title = 25

        self.kind_base: dict[PermutationType, int] = {
            PermutationType.HOMOGLYPH: 25,
            PermutationType.IDN: 25,
            PermutationType.SUBDOMAIN: 22,
            PermutationType.WWW_MERGE: 20,
            PermutationType.COMBO: 20,
            PermutationType.TYPO: 18,
            PermutationType.SOUNDSQUAT: 16,
            PermutationType.BITSQUAT: 15,
            PermutationType.HYPHEN: 12,
            PermutationType.VOWEL_SWAP: 14,
            PermutationType.PLURAL: 10,
            PermutationType.TLD_SWAP: 10,
        }

        if overrides:
            self._apply_overrides(overrides)

    def _apply_overrides(self, overrides: dict[str, Any]) -> None:
        for k, v in overrides.items():
            if k == "kind_base" and isinstance(v, dict):
                for p_name, val in v.items():
                    try:
                        p_type = PermutationType(p_name)
                        self.kind_base[p_type] = int(val)
                    except (ValueError, TypeError):
                        # An unknown technique name or a non-numeric weight is
                        # skipped rather than aborting the whole file, but say so
                        # under --debug: a silent drop looks like the override
                        # was applied.
                        _log.debug("ignoring kind_base override %r=%r", p_name, val)
            elif k == "kind_base":
                # A non-dict "kind_base" would otherwise be coerced to an int
                # and blow up later in _technique_points; ignore it instead.
                continue
            elif hasattr(self, k) and not k.startswith("_"):
                setattr(self, k, int(v))


# Heuristics for detecting parked domains / domains for sale.
_PARKING_TITLES = {
    "parked",
    "domain for sale",
    "this domain is available",
    "buy this domain",
    "hugedomains",
    "sedo",
    "dan.com",
    "afternic",
    "go daddy",
    "godaddy",
    "unregistered",
    "parkingcrew",
    "cashpark",
    "bodis",
    "domainname",
}
_PARKING_SERVERS = {"parkingcrew", "sedo", "bodis"}

# Age-based scoring thresholds. Single source of truth: reporters.py and
# html_report.py read from these constants instead of inlining the magic
# numbers (previously duplicated across all three modules).
AGE_FRESH_DAYS = 7
AGE_NEW_DAYS = 30
AGE_RECENT_DAYS = 90


def count_fresh(results: Iterable[DomainResult]) -> int:
    """Counts results whose WHOIS age is under AGE_FRESH_DAYS.

    Single source of truth for the three verdict renderers (terminal,
    Markdown, HTML) so they can't drift from each other or from the
    threshold they claim to report.
    """
    return sum(1 for r in results if r.age_days is not None and r.age_days < AGE_FRESH_DAYS)


def _detect_parking(result: DomainResult) -> None:
    """Sets ``result.is_parked`` based on title / Server header heuristics."""
    title = (result.page_title or "").lower()
    server = (result.server_header or "").lower()
    if any(sig in title for sig in _PARKING_TITLES) or any(
        sig in server for sig in _PARKING_SERVERS
    ):
        result.is_parked = True


def _detect_defensive(result: DomainResult, target: str) -> None:
    """Sets ``result.is_likely_defensive`` when the redirect points back to *target*."""
    if not (result.redirects_to and target):
        return
    parsed = parse_redirect(result.redirects_to)
    if parsed is None:
        # Unparseable Location from a hostile host — never treat that as proof
        # of a defensive registration, which would zero the risk score.
        return
    host, scheme = parsed
    canonical = target.lower().rstrip(".")
    if host and (host == canonical or host.endswith("." + canonical)):
        result.is_likely_defensive = True
        return
    if (
        not host
        and not scheme
        and (result.http_status is not None and 300 <= result.http_status < 400)
    ):
        # Relative-path Location header (e.g. "/") from a 3xx is same-origin.
        result.is_likely_defensive = True


def _title_similarity(t1: str, t2: str) -> float:
    """Computes Jaccard similarity of words between two titles."""
    w1 = set(re.findall(r"\w+", t1.lower()))
    w2 = set(re.findall(r"\w+", t2.lower()))
    if not w1 or not w2:
        return 0.0
    return len(w1 & w2) / len(w1 | w2)


def _title_points(
    result: DomainResult,
    reasons: list[str],
    weights: ScoringWeights,
    target_title: str | None = None,
) -> int:
    """Enriches result with title similarity and returns risk points if they match."""
    if not target_title or not result.page_title:
        return 0
    sim = _title_similarity(target_title, result.page_title)
    result.title_similarity = round(sim, 2)
    if sim >= 0.5:
        points = weights.points_cloned_title
        reasons.append(
            "cloned or highly similar page title to target "
            f"(similarity: {result.title_similarity:.2f}) (+{points})"
        )
        return points
    return 0


def _technique_points(result: DomainResult, reasons: list[str], weights: ScoringWeights) -> int:
    """Base points for the squatting technique (homoglyph/typo/combosquat/...)."""
    base = weights.kind_base.get(result.kind, 10)
    reasons.append(f"technique: {result.kind.value} (+{base})")
    return base


def _network_points(result: DomainResult, reasons: list[str], weights: ScoringWeights) -> int:
    """DNS + HTTP signals. Skipped entirely when the domain is parked."""
    if result.is_parked:
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
    """Points for an active TLS cert plus fresh-cert / SAN-mismatch boosts."""
    if not result.has_ssl:
        return 0
    points = weights.points_ssl
    reasons.append(f"active SSL certificate (+{weights.points_ssl})")
    if result.ssl_cert_age_days is not None and result.ssl_cert_age_days < AGE_FRESH_DAYS:
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
    """Bonus for a redirect Location header outside the 2xx/3xx range (which is already scored)."""
    if not result.redirects_to:
        return 0
    if result.http_status is not None and 200 <= result.http_status < 400:
        return 0
    reasons.append(f"redirects elsewhere (+{weights.points_redirect})")
    return weights.points_redirect


def _age_points(result: DomainResult, reasons: list[str], weights: ScoringWeights) -> int:
    """Points based on WHOIS-derived domain age (fresher = more phishing-likely)."""
    age = result.age_days
    if age is None:
        return 0
    if age < AGE_FRESH_DAYS:
        reasons.append(f"registered {age} days ago (+{weights.points_age_fresh})")
        return weights.points_age_fresh
    if age < AGE_NEW_DAYS:
        reasons.append(f"registered {age} days ago (+{weights.points_age_new})")
        return weights.points_age_new
    if age < AGE_RECENT_DAYS:
        reasons.append(f"registered {age} days ago (+{weights.points_age_recent})")
        return weights.points_age_recent
    return 0


def score(
    result: DomainResult,
    target: str = "",
    weights: ScoringWeights | None = None,
    target_title: str | None = None,
) -> DomainResult:
    """Computes risk_score, risk_level, reasons, and is_likely_defensive. Mutates and returns."""
    if not result.is_registered:
        result.risk_score = 0
        result.risk_level = RiskLevel.SAFE
        result.risk_reasons = []
        return result

    if weights is None:
        weights = ScoringWeights()

    _detect_parking(result)
    _detect_defensive(result, target)

    reasons: list[str] = []
    points = _technique_points(result, reasons, weights)
    points += _network_points(result, reasons, weights)
    if result.has_mx:
        points += weights.points_mx
        reasons.append(f"has an MX record — ready for email phishing (+{weights.points_mx})")
    points += _tls_points(result, reasons, weights)
    points += _redirect_points(result, reasons, weights)
    points += _age_points(result, reasons, weights)
    points += _title_points(result, reasons, weights, target_title)

    result.risk_score = min(points, 100)
    result.risk_level = RiskLevel.from_score(result.risk_score)

    if result.is_likely_defensive:
        result.risk_score = 0
        result.risk_level = RiskLevel.SAFE
        reasons.append("detected as a defensive registration redirecting to target (risk cleared)")

    result.risk_reasons = reasons
    return result
