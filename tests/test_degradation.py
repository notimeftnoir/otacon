"""Tests for DNS health accounting and the inconclusive verdict.

v2.0.0 reported a confident all-clear while resolving nothing: a swallowed
lookup error and a genuinely unregistered domain both produce an empty result.
These tests pin the distinction that makes the difference visible.
"""

from __future__ import annotations

import aiodns.error
import pytest
from rich.console import Console

from otacon.core.models import DEGRADED_RATIO, DomainResult, ScanReport
from otacon.core.types import PermutationType, RiskLevel
from otacon.net.dns import is_negative_answer
from otacon.net.resolver import Resolver
from otacon.reporters.console import _headline, _verdict_card
from otacon.utils.theme import OTACON_THEME

# ── telling an answer apart from a malfunction ──────────────────────────


@pytest.mark.parametrize("code", [1, 4])  # ARES_ENODATA, ARES_ENOTFOUND
def test_nxdomain_and_nodata_are_answers_not_failures(code: int) -> None:
    assert is_negative_answer(aiodns.error.DNSError(code, "nope")) is True


@pytest.mark.parametrize(
    "exc",
    [
        aiodns.error.DNSError(3, "server failure"),
        aiodns.error.DNSError(12, "timeout"),
        TypeError("'DNSResult' object is not iterable"),  # the aiodns 4 break
        TimeoutError(),
        ConnectionRefusedError(),
    ],
)
def test_everything_else_counts_as_a_failure(exc: BaseException) -> None:
    assert is_negative_answer(exc) is False


def test_dnserror_without_args_is_not_treated_as_an_answer() -> None:
    assert is_negative_answer(aiodns.error.DNSError()) is False


# ── the counters on the resolver ────────────────────────────────────────


@pytest.mark.asyncio
async def test_unregistered_domain_does_not_count_as_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    r = Resolver(check_http=False)

    async def nxdomain(*_a: object, **_k: object) -> object:
        raise aiodns.error.DNSError(4, "Domain name not found")

    monkeypatch.setattr("otacon.net.resolver._query_dns", nxdomain)
    assert await r._query_ips("nope.com", "A") == []
    assert r.dns_queries == 1
    assert r.dns_failures == 0


@pytest.mark.asyncio
async def test_library_break_counts_as_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """The exact shape of the aiodns 4 regression."""
    r = Resolver(check_http=False)

    async def broken(*_a: object, **_k: object) -> object:
        raise TypeError("'DNSResult' object is not iterable")

    monkeypatch.setattr("otacon.net.resolver._query_dns", broken)
    assert await r._query_ips("example.com", "A") == []
    assert r.dns_queries == 1
    assert r.dns_failures == 1


@pytest.mark.asyncio
async def test_successful_lookup_counts_only_as_a_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    r = Resolver(check_http=False)

    class _Rec:
        host = "1.2.3.4"

    async def ok(*_a: object, **_k: object) -> list[object]:
        return [_Rec()]

    monkeypatch.setattr("otacon.net.resolver._query_dns", ok)
    assert await r._query_ips("example.com", "A") == ["1.2.3.4"]
    assert (r.dns_queries, r.dns_failures) == (1, 0)


# ── the report-level verdict ────────────────────────────────────────────


def test_healthy_scan_is_not_degraded() -> None:
    # A real scan of example.com measured ~5% failures from timeouts on junk
    # domains; the threshold must sit clear of that.
    report = ScanReport(target="example.com", dns_queries=482, dns_failures=24)
    assert report.dns_failure_ratio < DEGRADED_RATIO
    assert report.degraded is False


def test_total_failure_is_degraded() -> None:
    report = ScanReport(target="example.com", dns_queries=478, dns_failures=478)
    assert report.degraded is True


def test_a_scan_with_no_lookups_is_not_degraded() -> None:
    """Guards against a division by zero and against flagging an empty run."""
    assert ScanReport(target="example.com").degraded is False


def test_degraded_verdict_replaces_the_all_clear() -> None:
    broken = ScanReport(
        target="example.com", total_permutations=239, dns_queries=478, dns_failures=478
    )
    style, headline, explanation = _headline(broken)
    assert style == "warn"
    assert "All clear" not in headline
    assert "Inconclusive" in headline
    assert "100%" in headline
    assert "may simply not have been checked" in explanation


def test_healthy_empty_scan_still_reads_as_all_clear() -> None:
    healthy = ScanReport(
        target="example.com", total_permutations=239, dns_queries=478, dns_failures=3
    )
    _style, headline, _explanation = _headline(healthy)
    assert "All clear" in headline


def test_degraded_warning_outranks_findings() -> None:
    """Results found while the resolver is failing are still incomplete."""
    report = ScanReport(
        target="example.com",
        total_permutations=239,
        results=[
            DomainResult(
                domain="examp1e.com",
                kind=PermutationType.HOMOGLYPH,
                resolves=True,
                ip_addresses=["1.2.3.4"],
                risk_score=90,
                risk_level=RiskLevel.CRITICAL,
            )
        ],
        dns_queries=478,
        dns_failures=400,
    )
    _style, headline, _explanation = _headline(report)
    assert "Inconclusive" in headline


def test_verdict_card_renders_the_warning() -> None:
    console = Console(theme=OTACON_THEME, width=90, record=True)
    console.print(
        _verdict_card(
            ScanReport(
                target="example.com", total_permutations=239, dns_queries=478, dns_failures=478
            )
        )
    )
    out = console.export_text()
    assert "Inconclusive" in out
    assert "478 of 478" in out


def test_counters_survive_a_json_round_trip() -> None:
    report = ScanReport(target="example.com", dns_queries=482, dns_failures=24)
    restored = ScanReport.model_validate_json(report.model_dump_json())
    assert (restored.dns_queries, restored.dns_failures) == (482, 24)
    assert restored.degraded is False


def test_an_older_report_without_counters_still_loads() -> None:
    """Reports written by 2.1.0 and earlier carry neither field."""
    legacy = '{"target": "example.com", "started_at": "2026-10-01T00:00:00Z", "results": []}'
    restored = ScanReport.model_validate_json(legacy)
    assert (restored.dns_queries, restored.dns_failures) == (0, 0)
    assert restored.degraded is False
