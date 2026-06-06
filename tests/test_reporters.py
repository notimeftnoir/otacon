"""Tests for the reporter output generation."""

from __future__ import annotations

from datetime import datetime, timezone
from io import StringIO

from otacon.models import DomainResult, PermutationType, ScanReport
from otacon.reporters import (
    _age_cell,
    _check,
    _domain_cell,
    _http_cell,
    _redirect_host,
    _risk_bar,
    render_table,
    to_json,
    to_markdown,
)
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


def _make_console(no_color: bool = True):
    from otacon.theme import OTACON_THEME
    from rich.console import Console

    buf = StringIO()
    return Console(file=buf, no_color=no_color, theme=OTACON_THEME, width=120), buf


def test_render_table_footer_shows_medium_count():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=40,
        risk_level=RiskLevel.MEDIUM,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    assert "med:" in buf.getvalue()


def test_render_table_shows_defensive_flag():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exampl.com",
        kind=PermutationType.TYPO,
        resolves=True,
        is_likely_defensive=True,
        redirects_to="https://example.com/",
        risk_score=28,
        risk_level=RiskLevel.LOW,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    assert "⚑" in buf.getvalue()


def test_render_table_no_defensive_flag_when_not_defensive():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exampl.com",
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=28,
        risk_level=RiskLevel.LOW,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    assert "⚑" not in buf.getvalue()


def test_render_table_shows_risk_bar_characters():
    report = ScanReport(target="example.com", total_permutations=5)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=50,
        risk_level=RiskLevel.MEDIUM,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    output = buf.getvalue()
    assert "█" in output
    assert "░" in output


# ---------------------------------------------------------------------------
# Age column
# ---------------------------------------------------------------------------

def test_age_cell_none_returns_dash():
    assert _age_cell(None).plain == "—"


def test_age_cell_6_days():
    assert _age_cell(6).plain == "6d"


def test_age_cell_90_days_is_3_months():
    assert _age_cell(90).plain == "3mo"


def test_age_cell_730_days_is_2_years():
    assert _age_cell(730).plain == "2y"


def test_render_table_has_age_column_header():
    report = ScanReport(target="example.com", total_permutations=5)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=28,
        risk_level=RiskLevel.LOW,
        age_days=6,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    output = buf.getvalue()
    assert "Age" in output
    assert "6d" in output


def test_render_table_age_none_does_not_crash():
    report = ScanReport(target="example.com", total_permutations=5)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=28,
        risk_level=RiskLevel.LOW,
        # age_days is None (default)
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    assert "Age" in buf.getvalue()


def test_json_export_includes_created_at():
    created = datetime(2024, 1, 15, tzinfo=timezone.utc)
    report = ScanReport(target="example.com", total_permutations=5)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        created_at=created,
        age_days=6,
        risk_score=28,
        risk_level=RiskLevel.LOW,
    )
    report.results.append(r)
    json_str = to_json(report)
    assert "created_at" in json_str
    assert "2024-01-15" in json_str
    assert "age_days" in json_str


# ---------------------------------------------------------------------------
# Page title (Task 03)
# ---------------------------------------------------------------------------

def test_domain_cell_shows_page_title_for_high_risk():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        page_title="Sign in to Google",
        risk_level=RiskLevel.HIGH,
    )
    cell = _domain_cell(r)
    assert "Sign in to Google" in cell.plain


def test_domain_cell_shows_page_title_for_critical_risk():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        page_title="Verify your account",
        risk_level=RiskLevel.CRITICAL,
    )
    cell = _domain_cell(r)
    assert "Verify your account" in cell.plain


def test_domain_cell_hides_page_title_for_medium_risk():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        page_title="Some page",
        risk_level=RiskLevel.MEDIUM,
    )
    cell = _domain_cell(r)
    assert "Some page" not in cell.plain


def test_domain_cell_no_title_no_extra_line():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        page_title=None,
        risk_level=RiskLevel.HIGH,
    )
    cell = _domain_cell(r)
    # Only domain + newline + technique — no third line
    assert cell.plain == "googel.com\ntypo"


def test_json_export_includes_page_title():
    report = ScanReport(target="example.com", total_permutations=5)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        page_title="Login - ExampleBank",
        risk_score=68,
        risk_level=RiskLevel.HIGH,
    )
    report.results.append(r)
    json_str = to_json(report)
    assert "page_title" in json_str
    assert "Login - ExampleBank" in json_str
