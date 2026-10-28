"""Tests for the shared verdict layer.

The console reporter and the overview screen must say the same thing about the
same scan. They used to be able to disagree because only the console had an
opinion at all; now both read this module, and these tests hold the wording
and the comparison logic that both depend on.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from otacon.core.models import DomainResult, ScanReport
from otacon.core.types import PermutationType, RiskLevel
from otacon.reporters import console as reporters
from otacon.triage.verdict import delta, reasons, verdict, worst_first


def _r(domain: str, score: int, level: RiskLevel, **kw: object) -> DomainResult:
    kw.setdefault("ip_addresses", ["1.2.3.4"])
    return DomainResult(
        domain=domain,
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=score,
        risk_level=level,
        **kw,  # type: ignore[arg-type]
    )


def _report(*results: DomainResult, **kw: object) -> ScanReport:
    return ScanReport(target="example.com", total_permutations=200, results=list(results), **kw)  # type: ignore[arg-type]


# ── the verdict itself ──────────────────────────────────────────────────


def test_clean_scan_says_all_clear() -> None:
    v = verdict(_report())
    assert v.tone == "ok"
    assert "All clear" in v.headline


def test_dangerous_scan_counts_only_the_dangerous_ones() -> None:
    v = verdict(
        _report(
            _r("a.com", 95, RiskLevel.CRITICAL),
            _r("b.com", 70, RiskLevel.HIGH),
            _r("c.com", 20, RiskLevel.LOW),
        )
    )
    assert v.tone == "danger"
    assert v.headline.startswith("⚠ 2 lookalikes")


def test_one_dangerous_lookalike_reads_as_singular() -> None:
    """'1 lookalikes look dangerous' is the kind of thing that costs trust."""
    v = verdict(_report(_r("a.com", 95, RiskLevel.CRITICAL)))
    assert "1 lookalike of" in v.headline
    assert "looks dangerous" in v.headline


def test_broken_resolver_is_never_reported_as_clean() -> None:
    """An empty result and an unanswered one look identical from the outside."""
    v = verdict(_report(dns_queries=100, dns_failures=90))
    assert v.degraded
    assert "Inconclusive" in v.headline
    assert "All clear" not in v.headline


def test_console_headline_is_the_same_verdict() -> None:
    """Two surfaces, one wording — the whole reason this module exists."""
    report = _report(_r("a.com", 95, RiskLevel.CRITICAL), _r("b.com", 20, RiskLevel.LOW))
    v = verdict(report)
    assert reporters._headline(report) == (v.tone, v.headline, v.explanation)


# ── what to do first ────────────────────────────────────────────────────


def test_worst_first_ranks_by_score_and_drops_the_harmless() -> None:
    report = _report(
        _r("mid.com", 50, RiskLevel.MEDIUM),
        _r("worst.com", 95, RiskLevel.CRITICAL),
        _r("zero.com", 0, RiskLevel.SAFE),
    )
    assert [r.domain for r in worst_first(report)] == ["worst.com", "mid.com"]


def test_reasons_are_words_rather_than_markers() -> None:
    """The table has four characters per flag; the overview has room for English."""
    r = _r(
        "a.com",
        95,
        RiskLevel.CRITICAL,
        has_login_form=True,
        favicon_matches_target=True,
        dnsbl_listed=True,
    )
    assert reasons(r) == "listed, cloned favicon, login form"


def test_reasons_never_comes_back_empty() -> None:
    """A blank line beside a domain tells the reader nothing at all."""
    assert reasons(_r("a.com", 15, RiskLevel.LOW))


# ── what changed since last time ────────────────────────────────────────


def _two_reports() -> tuple[ScanReport, ScanReport]:
    earlier = datetime.now(UTC) - timedelta(days=3)
    before = ScanReport(
        target="example.com",
        started_at=earlier,
        total_permutations=200,
        results=[
            DomainResult(domain="fresh.com", kind=PermutationType.TYPO),  # unregistered
            _r("worse.com", 30, RiskLevel.LOW),
            _r("gone.com", 40, RiskLevel.MEDIUM),
        ],
    )
    after = _report(
        _r("fresh.com", 85, RiskLevel.CRITICAL),
        _r("worse.com", 90, RiskLevel.CRITICAL),
        DomainResult(domain="gone.com", kind=PermutationType.TYPO),
    )
    return before, after


def test_delta_reports_registration_escalation_and_disappearance() -> None:
    before, after = _two_reports()
    found = {c.domain: c.detail for c in delta(before, after).changes}
    assert found["fresh.com"] == "newly registered"
    assert found["worse.com"] == "risk rose low to critical"
    assert found["gone.com"] == "no longer registered"


def test_delta_is_quiet_when_nothing_moved() -> None:
    """Re-running a scan on a quiet week must not invent news."""
    report = _report(_r("a.com", 50, RiskLevel.MEDIUM))
    assert delta(report, report).quiet


@pytest.mark.parametrize("field", ["ip_addresses", "server_header"])
def test_delta_ignores_churn_that_is_not_about_risk(field: str) -> None:
    """compute_diff reports these; here they would bury the lines that matter.

    A CDN-hosted lookalike changes IP constantly, and an overview that leads
    with that is an overview nobody reads twice.
    """
    before = _report(_r("a.com", 50, RiskLevel.MEDIUM, ip_addresses=["1.1.1.1"]))
    changed = {"ip_addresses": ["9.9.9.9"], "server_header": "other"}[field]
    after = _report(_r("a.com", 50, RiskLevel.MEDIUM, **{field: changed}))  # type: ignore[arg-type]
    assert delta(before, after).quiet
