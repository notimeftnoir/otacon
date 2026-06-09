"""Tests for the HTML report generator."""
from __future__ import annotations

from datetime import datetime, timezone

from otacon.html_report import to_html
from otacon.models import DomainResult, PermutationType, ScanReport
from otacon.theme import RiskLevel


def _report(*results: DomainResult, total: int = 10) -> ScanReport:
    return ScanReport(
        target="example.com",
        total_permutations=total,
        results=list(results),
        started_at=datetime(2024, 6, 1, 12, 0, tzinfo=timezone.utc),
    )


def _result(
    domain: str = "evil-example.com",
    kind: PermutationType = PermutationType.COMBO,
    resolves: bool = True,
    score: int = 50,
    level: RiskLevel = RiskLevel.MEDIUM,
    **kwargs,
) -> DomainResult:
    return DomainResult(
        domain=domain, kind=kind, resolves=resolves,
        risk_score=score, risk_level=level, **kwargs,
    )


# ---------------------------------------------------------------------------
# Basic structure
# ---------------------------------------------------------------------------

def test_to_html_returns_string():
    out = to_html(_report())
    assert isinstance(out, str)


def test_to_html_has_doctype():
    assert to_html(_report()).startswith("<!DOCTYPE html>")


def test_to_html_has_title_with_target():
    out = to_html(_report())
    assert "<title>Otacon — example.com</title>" in out


def test_to_html_has_inline_css():
    out = to_html(_report())
    assert "<style>" in out
    assert "--bg:" in out


def test_to_html_has_closing_body():
    out = to_html(_report())
    assert "</body>" in out
    assert "</html>" in out


# ---------------------------------------------------------------------------
# Verdict section
# ---------------------------------------------------------------------------

def test_to_html_clean_verdict_when_no_results():
    out = to_html(_report())
    assert "clean" in out
    assert "none registered" in out


def test_to_html_registered_count_in_verdict():
    r = _result()
    out = to_html(_report(r))
    assert "1 registered" in out


def test_to_html_crit_count_in_verdict():
    r = _result(score=90, level=RiskLevel.CRITICAL)
    out = to_html(_report(r))
    assert "crit: 1" in out


def test_to_html_mx_count_in_verdict():
    r = _result(has_mx=True)
    out = to_html(_report(r))
    assert "mx: 1" in out


def test_to_html_fresh_count_in_verdict():
    r = _result(age_days=3)
    out = to_html(_report(r))
    assert "fresh" in out
    assert "1" in out


# ---------------------------------------------------------------------------
# Table content
# ---------------------------------------------------------------------------

def test_to_html_registered_domain_in_table():
    r = _result(domain="fakeexample.com")
    out = to_html(_report(r))
    assert "fakeexample.com" in out


def test_to_html_domain_is_hyperlinked():
    r = _result(domain="fakeexample.com")
    out = to_html(_report(r))
    assert 'href="https://fakeexample.com"' in out


def test_to_html_page_title_shown():
    r = _result(page_title="Login — FakeBank")
    out = to_html(_report(r))
    assert "Login — FakeBank" in out


def test_to_html_risk_reasons_in_details():
    r = _result(risk_reasons=["has MX (+25)", "SSL (+15)"])
    out = to_html(_report(r))
    assert "<details>" in out
    assert "has MX (+25)" in out
    assert "SSL (+15)" in out


def test_to_html_defensive_flag_shown():
    r = _result(
        is_likely_defensive=True,
        redirects_to="https://example.com",
    )
    out = to_html(_report(r))
    assert "⚑" in out


def test_to_html_age_fresh_styled_as_danger():
    r = _result(age_days=5)
    out = to_html(_report(r))
    assert "age-fresh" in out
    assert "5d" in out


def test_to_html_age_old_not_fresh():
    r = _result(age_days=365)
    out = to_html(_report(r))
    assert "1y" in out


def test_to_html_http_status_shown():
    r = _result(http_status=200)
    out = to_html(_report(r))
    assert "200" in out
    assert "http-2xx" in out


def test_to_html_no_registered_shows_no_table():
    out = to_html(_report())
    assert "<table>" not in out
    assert "No registered variants detected" in out


# ---------------------------------------------------------------------------
# XSS / escaping
# ---------------------------------------------------------------------------

def test_to_html_escapes_domain_special_chars():
    r = _result(domain="evil<script>.com")
    out = to_html(_report(r))
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_to_html_escapes_page_title():
    r = _result(page_title='<img src=x onerror="alert(1)">')
    out = to_html(_report(r))
    assert "<img" not in out
    assert "&lt;img" in out


def test_to_html_escapes_target_in_title():
    report = _report()
    report = ScanReport(target='evil">.com', total_permutations=0)
    out = to_html(report)
    assert '">' not in out.split("<title>")[1].split("</title>")[0]


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

def test_scan_html_flag_writes_file(tmp_path, monkeypatch):
    from unittest.mock import AsyncMock, patch

    from typer.testing import CliRunner

    from otacon.cli import app

    monkeypatch.chdir(tmp_path)
    out_file = tmp_path / "report.html"
    empty_report = ScanReport(target="example.com", total_permutations=0)

    runner = CliRunner()
    with patch("otacon.cli._run_scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = empty_report
        result = runner.invoke(app, ["scan", "example.com", "--html", "report.html"])

    assert out_file.exists(), f"HTML not written. CLI output: {result.output}"
    content = out_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "example.com" in content
