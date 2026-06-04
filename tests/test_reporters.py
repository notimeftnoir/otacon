"""Tests for the reporter output generation."""

from __future__ import annotations

from otacon.models import DomainResult, PermutationType, ScanReport
from otacon.reporters import to_markdown
from otacon.theme import RiskLevel


def test_to_markdown_no_threats_contains_clear_message() -> None:
    report = ScanReport(target="example.com", total_permutations=10, results=[])

    markdown = to_markdown(report)

    assert "No suspicious registered variants detected." in markdown
    assert "**Target:** `example.com`" in markdown


def test_to_markdown_includes_detected_threat() -> None:
    result = DomainResult(
        domain="login.example.com",
        kind=PermutationType.COMBO,
        note="appended bait word",
        resolves=True,
        ip_addresses=["1.2.3.4"],
        risk_score=40,
        risk_level=RiskLevel.MEDIUM,
    )
    report = ScanReport(target="example.com", total_permutations=5, results=[result])

    markdown = to_markdown(report)

    assert "| `login.example.com` | combosquat | 40 (medium) | DNS |" in markdown


from otacon.reporters import _check, _domain_cell, _http_cell, _redirect_host, _risk_bar
from otacon.models import DomainResult, PermutationType


def test_risk_bar_full_score():
    assert _risk_bar(100, "ok").plain == "████████ 100"


def test_risk_bar_zero_score():
    assert _risk_bar(0, "ok").plain == "░░░░░░░░   0"


def test_risk_bar_half_score():
    assert _risk_bar(50, "warn").plain == "████░░░░  50"


def test_risk_bar_75():
    assert _risk_bar(75, "danger").plain == "██████░░  75"


def test_risk_bar_25():
    assert _risk_bar(25, "info").plain == "██░░░░░░  25"


def test_check_true_shows_checkmark():
    assert _check(True).plain == "✓"


def test_check_false_shows_dash():
    assert _check(False).plain == "—"


def test_http_cell_none():
    assert _http_cell(None).plain == "—"


def test_http_cell_200():
    assert _http_cell(200).plain == "200"


def test_http_cell_301():
    assert _http_cell(301).plain == "301"


def test_http_cell_404():
    assert _http_cell(404).plain == "404"


def test_http_cell_500():
    assert _http_cell(500).plain == "500"


def test_redirect_host_extracts_netloc():
    assert _redirect_host("https://www.google.com/search?q=1") == "www.google.com"


def test_redirect_host_fallback_for_bare_string():
    assert _redirect_host("not-a-url") == "not-a-url"


def test_redirect_host_empty_string():
    assert _redirect_host("") == ""


def test_domain_cell_contains_domain_and_technique():
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)
    cell = _domain_cell(r)
    assert "googel.com" in cell.plain
    assert "typo" in cell.plain


def test_domain_cell_defensive_shows_flag_and_host():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        redirects_to="https://google.com/",
        is_likely_defensive=True,
    )
    cell = _domain_cell(r)
    assert "⚑" in cell.plain
    assert "google.com" in cell.plain


def test_domain_cell_non_defensive_no_flag():
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)
    cell = _domain_cell(r)
    assert "⚑" not in cell.plain
