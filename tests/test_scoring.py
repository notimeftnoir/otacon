"""Tests for the risk scoring engine."""

from __future__ import annotations

import pytest

from otacon.models import DomainResult, PermutationType
from otacon.scoring import score
from otacon.theme import RiskLevel


def test_score_unregistered_is_safe() -> None:
    result = DomainResult(domain="example.com", kind=PermutationType.TYPO)

    scored = score(result)

    assert scored.risk_score == 0
    assert scored.risk_level == RiskLevel.SAFE
    assert scored.risk_reasons == []


def test_score_resolves_with_typo_is_low_risk() -> None:
    result = DomainResult(
        domain="gogle.com",
        kind=PermutationType.TYPO,
        resolves=True,
        ip_addresses=["1.2.3.4"],
    )

    scored = score(result)

    assert scored.risk_score == 28
    assert scored.risk_level == RiskLevel.LOW
    assert "resolves to an IP" in scored.risk_reasons[1]


def test_score_full_infrastructure_is_high_risk() -> None:
    result = DomainResult(
        domain="example-login.com",
        kind=PermutationType.COMBO,
        resolves=True,
        ip_addresses=["1.2.3.4"],
        has_mx=True,
        mx_records=["mail.example-login.com"],
        has_ssl=True,
        http_status=200,
        redirects_to="https://example.com",
    )

    scored = score(result)

    assert scored.risk_score == 85
    assert scored.risk_level == RiskLevel.CRITICAL
    assert any("has an MX record" in reason for reason in scored.risk_reasons)
    assert any("responds HTTP 200" in reason for reason in scored.risk_reasons)


def test_domain_result_is_likely_defensive_defaults_to_false():
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)
    assert r.is_likely_defensive is False


def test_score_sets_is_likely_defensive_when_redirect_matches_target():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        redirects_to="https://www.google.com/",
    )
    result = score(r, target="google.com")
    assert result.is_likely_defensive is True
    assert result.risk_score == 0
    assert result.risk_level == RiskLevel.SAFE


def test_score_does_not_set_defensive_for_unrelated_redirect():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        redirects_to="https://www.phishing.com/",
    )
    result = score(r, target="google.com")
    assert result.is_likely_defensive is False


def test_score_does_not_set_defensive_when_target_is_empty():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        redirects_to="https://www.google.com/",
    )
    result = score(r, target="")
    assert result.is_likely_defensive is False


def test_score_backward_compatible_no_target():
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO, resolves=True)
    result = score(r)  # no target — must not raise
    assert result.is_likely_defensive is False


def test_score_http_2xx_gives_fifteen_points():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        http_status=200,
    )
    result = score(r)
    # base=18 (typo) + 10 (resolves) + 15 (HTTP 200) = 43
    assert result.risk_score == 43


def test_score_http_3xx_gives_ten_points():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        http_status=301,
    )
    result = score(r)
    # base=18 + 10 (resolves) + 10 (HTTP 301) = 38
    assert result.risk_score == 38


def test_score_http_4xx_gives_five_points():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        http_status=404,
    )
    result = score(r)
    # base=18 + 10 (resolves) + 5 (HTTP 404) = 33
    assert result.risk_score == 33


def test_score_http_5xx_gives_three_points():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        http_status=500,
    )
    result = score(r)
    # base=18 + 10 (resolves) + 3 (HTTP 500) = 31
    assert result.risk_score == 31


def test_score_3xx_with_redirect_does_not_double_count():
    """HTTP 3xx already captures the redirect signal — redirects_to must not add +5 on top."""
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        http_status=301,
        redirects_to="https://somewhere.com/",
    )
    result = score(r)
    # base=18 + 10 (resolves) + 10 (HTTP 301) = 38, NOT 43
    assert result.risk_score == 38


def test_score_2xx_with_location_header_does_not_add_redirect_bonus():
    """A 2xx response already scored +15; the redirect +5 bonus must not double-count."""
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        http_status=200,
        redirects_to="https://somewhere.com/",
    )
    result = score(r)
    # base=18 + 10 (resolves) + 15 (HTTP 200) = 43; redirect bonus suppressed for 2xx
    assert result.risk_score == 43


def test_score_defensive_detection_ignores_trailing_dot_in_target():
    """A trailing dot on the target (FQDN notation) must not prevent defensive detection."""
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        redirects_to="https://www.google.com/",
    )
    result = score(r, target="google.com.")  # trailing dot — FQDN notation
    assert result.is_likely_defensive is True


def test_score_relative_redirect_3xx_sets_defensive():
    """A relative-path Location header (e.g. '/') on a 3xx is same-origin — defensive."""
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        http_status=301,
        redirects_to="/",  # relative path — no hostname
    )
    result = score(r, target="google.com")
    assert result.is_likely_defensive is True
    assert result.risk_score == 0
    assert result.risk_level == RiskLevel.SAFE


def test_score_relative_redirect_2xx_does_not_set_defensive():
    """A relative-path Location on a 2xx is not a redirect — must not set defensive flag."""
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        http_status=200,
        redirects_to="/",
    )
    result = score(r, target="google.com")
    assert result.is_likely_defensive is False


# ---------------------------------------------------------------------------
# Domain-age scoring modifier
# ---------------------------------------------------------------------------


def test_score_age_under_7_days_adds_20():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        age_days=5,
    )
    result = score(r)
    # base=18 (typo) + 10 (resolves) + 20 (age <7d) = 48
    assert result.risk_score == 48
    assert any("registered 5 days ago" in reason for reason in result.risk_reasons)
    assert any("+20" in reason for reason in result.risk_reasons)


def test_score_age_7_to_29_days_adds_12():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        age_days=15,
    )
    result = score(r)
    # base=18 + 10 + 12 = 40
    assert result.risk_score == 40
    assert any("+12" in reason for reason in result.risk_reasons)


def test_score_age_30_to_89_days_adds_5():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        age_days=60,
    )
    result = score(r)
    # base=18 + 10 + 5 = 33
    assert result.risk_score == 33
    assert any("+5" in reason for reason in result.risk_reasons)


def test_score_age_90_plus_days_adds_nothing():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        age_days=120,
    )
    result = score(r)
    # base=18 + 10 = 28; no age modifier
    assert result.risk_score == 28


def test_score_age_exactly_7_days_adds_12():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        age_days=7,
    )
    result = score(r)
    # <7 threshold is exclusive: 7 falls in the <30 bucket (+12)
    assert result.risk_score == 40


def test_score_age_exactly_30_days_adds_5():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        age_days=30,
    )
    result = score(r)
    # <30 is exclusive; 30 falls in the <90 bucket (+5)
    assert result.risk_score == 33


def test_score_missing_age_no_modifier():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,  # age_days is None (default)
    )
    result = score(r)
    # base=18 + 10 = 28; no age penalty for unknown age
    assert result.risk_score == 28


# ---------------------------------------------------------------------------
# RiskLevel.rank — ordering for threshold comparisons
# ---------------------------------------------------------------------------


def test_risk_level_rank_safe_is_zero():
    assert RiskLevel.SAFE.rank == 0


def test_risk_level_rank_critical_is_four():
    assert RiskLevel.CRITICAL.rank == 4


def test_risk_level_rank_strict_ascending_order():
    levels = [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    ranks = [lv.rank for lv in levels]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == 5  # all distinct


def test_risk_level_rank_comparable_via_ge():
    assert RiskLevel.HIGH.rank >= RiskLevel.MEDIUM.rank
    assert RiskLevel.LOW.rank < RiskLevel.HIGH.rank


# ---------------------------------------------------------------------------
# Parking detection tests
# ---------------------------------------------------------------------------


def test_score_detects_parked_domain_by_title():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        http_status=200,
        page_title="Domain is parked",
    )
    result = score(r)
    assert result.is_parked is True
    # base=18, HTTP and Resolves (15+10) are skipped.
    assert result.risk_score == 18
    assert any("detected as parked domain" in reason for reason in result.risk_reasons)


def test_score_detects_parked_domain_by_server_header():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        http_status=200,
        server_header="ParkingCrew",
    )
    result = score(r)
    assert result.is_parked is True
    assert result.risk_score == 18


def test_score_parked_domain_retains_mx_points():
    """A parked domain with MX is still a risk (phishing)."""
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        http_status=200,
        page_title="Sedo Parking",
        has_mx=True,
    )
    result = score(r)
    assert result.is_parked is True
    # base=18 + 25 (MX) = 43. (HTTP and Resolves are skipped)
    assert result.risk_score == 43


def test_score_parked_domain_with_ssl_points():
    """Active SSL on a parked domain is still scored (+15)."""
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        http_status=200,
        page_title="Domain For Sale",
        has_ssl=True,
    )
    result = score(r)
    assert result.is_parked is True
    # base=18 + 15 (SSL) = 33
    assert result.risk_score == 33


def test_www_merge_has_explicit_weight() -> None:
    """WWW_MERGE must have its own weight in ScoringWeights().kind_base, not the anonymous fallback.

    It's a close, deceptive visual match (dot omission on a trusted 'www.'
    prefix) and deserves a deliberate score, not whatever the default happens
    to be for an unlisted technique.
    """
    from otacon.scoring import ScoringWeights

    kind_base = ScoringWeights().kind_base
    assert PermutationType.WWW_MERGE in kind_base

    r = DomainResult(
        domain="wwwexample.com",
        kind=PermutationType.WWW_MERGE,
        resolves=True,
        ip_addresses=["1.2.3.4"],
    )
    result = score(r)
    weight = kind_base[PermutationType.WWW_MERGE]
    assert f"technique: www-merge (+{weight})" in result.risk_reasons[0]


def test_scoring_weights_custom_overrides() -> None:
    """ScoringWeights accepts overrides and integrates them."""
    from otacon.scoring import ScoringWeights

    weights = ScoringWeights(
        {
            "points_mx": 100,
            "points_resolves": 50,
            "kind_base": {
                "homoglyph": 99,
            },
        }
    )
    assert weights.points_mx == 100
    assert weights.points_resolves == 50
    assert weights.points_ssl == 15  # remains default
    assert weights.kind_base[PermutationType.HOMOGLYPH] == 99
    assert weights.kind_base[PermutationType.TYPO] == 18  # remains default


def test_title_similarity_and_scoring() -> None:
    """Testing Jaccard title similarity scoring."""
    from otacon.scoring import _title_similarity

    assert _title_similarity("GitHub - Security", "GitHub - Security") == 1.0
    assert _title_similarity("GitHub - Security", "Github - Security Update") == 2 / 3
    assert _title_similarity("Google", "Yahoo") == 0.0

    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        page_title="GitHub - Security Update",
    )
    result = score(r, target="github.com", target_title="GitHub - Security")
    assert result.title_similarity == 0.67
    assert any("cloned or highly similar page title" in reason for reason in result.risk_reasons)


# ---------------------------------------------------------------------------
# ScoringWeights — malformed --weights-file values must not raise a raw
# unhandled TypeError; see cli._load_weights for where this is turned into a
# clean typer.BadParameter for the top-level fields.
# ---------------------------------------------------------------------------


def test_scoring_weights_non_numeric_top_level_override_raises() -> None:
    from otacon.scoring import ScoringWeights

    with pytest.raises((TypeError, ValueError)):
        ScoringWeights({"points_mx": None})

    with pytest.raises((TypeError, ValueError)):
        ScoringWeights({"points_mx": ["not", "a", "number"]})


def test_scoring_weights_skips_bad_kind_base_entries_without_crashing() -> None:
    """A malformed value for one technique inside kind_base must not abort the
    whole file — only that entry is skipped, matching the existing behaviour
    for an unrecognised technique name."""
    from otacon.scoring import ScoringWeights

    weights = ScoringWeights({"kind_base": {"typo": None, "homoglyph": 42}})
    assert weights.kind_base[PermutationType.HOMOGLYPH] == 42
    assert weights.kind_base[PermutationType.TYPO] == 18  # untouched default, entry was skipped
