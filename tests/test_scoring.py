"""Tests for the risk scoring engine."""

from __future__ import annotations

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

    assert scored.risk_score == 90
    assert scored.risk_level == RiskLevel.CRITICAL
    assert any("has an MX record" in reason for reason in scored.risk_reasons)
    assert any("responds HTTP 200" in reason for reason in scored.risk_reasons)
