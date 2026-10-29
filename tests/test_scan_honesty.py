"""A scan must not claim to know what it never checked.

One theme, four surfaces. A report that does not record which probes it ran
cannot be compared against another one, cannot tell the console how to re-probe
a row, and cannot tell the reader that a reputation list declined to answer.
Every case here is a place where silence used to read as an all-clear.
"""

from __future__ import annotations

import pytest

from otacon.core.models import DomainResult, ScanOptions, ScanReport
from otacon.core.types import PermutationType
from otacon.triage.actions import rescan_result


@pytest.fixture
def built(monkeypatch):
    """Records the options every Resolver is built with, and probes nothing."""
    import otacon.net.resolver as resolver_mod

    seen: list[dict[str, bool]] = []
    real_init = resolver_mod.Resolver.__init__

    def spy(self, concurrency=50, check_http=True, target="", check_whois=True, check_dnsbl=True):
        seen.append({"http": check_http, "whois": check_whois, "dnsbl": check_dnsbl})
        real_init(self, concurrency, check_http, target, check_whois, check_dnsbl)

    async def no_title(self):
        return None

    async def one_result(self, perm):
        return DomainResult(domain=perm.domain, kind=perm.kind, resolves=True)

    monkeypatch.setattr(resolver_mod.Resolver, "__init__", spy)
    monkeypatch.setattr(resolver_mod.Resolver, "_fetch_target_title", no_title)
    monkeypatch.setattr(resolver_mod.Resolver, "check_one", one_result)
    return seen


_ROW = DomainResult(domain="examp1e.com", kind=PermutationType.HOMOGLYPH)


@pytest.mark.asyncio
async def test_rescan_carries_the_scans_options(built) -> None:
    """A row from a DNS-only scan must be re-probed DNS-only."""
    dns_only = ScanOptions(http=False, whois=False, dnsbl=False, ct=False)
    await rescan_result(_ROW, "example.com", dns_only)
    assert built == [{"http": False, "whois": False, "dnsbl": False}]


@pytest.mark.asyncio
async def test_rescan_without_options_probes_everything(built) -> None:
    """No options given is a full scan — the documented default."""
    await rescan_result(_ROW, "example.com")
    assert built == [{"http": True, "whois": True, "dnsbl": True}]


@pytest.mark.asyncio
async def test_rescan_rescores_the_row(built) -> None:
    updated = await rescan_result(_ROW, "example.com")
    assert updated.domain == "examp1e.com"
    assert updated.resolves is True
    assert updated.risk_score > 0, "a resolving homoglyph must score above zero"


@pytest.mark.asyncio
async def test_a_fresh_report_defaults_to_a_full_scan() -> None:
    """ScanOptions defaults keep a report stored before this field reading as it did."""
    restored = ScanReport.model_validate_json(ScanReport(target="example.com").model_dump_json())
    assert restored.options == ScanOptions(http=True, whois=True, dnsbl=True, ct=True)


def test_a_report_without_an_options_field_still_loads() -> None:
    """Reports written by 3.0.0 have no `options` key; they must not fail to open."""
    legacy = '{"target":"example.com","started_at":"2026-01-01T00:00:00Z","results":[]}'
    assert ScanReport.model_validate_json(legacy).options == ScanOptions()


# ---------------------------------------------------------------------------
# diff across scans that did not check the same things
# ---------------------------------------------------------------------------


def _report(options: ScanOptions, **row: object) -> ScanReport:
    base = dict(domain="examp1e.com", kind=PermutationType.HOMOGLYPH, resolves=True)
    return ScanReport(target="example.com", options=options, results=[DomainResult(**base, **row)])


def test_diff_does_not_invent_losses_when_http_was_skipped() -> None:
    """A full scan against a --no-http one must not report a lost certificate."""
    from otacon.diff import compute_diff

    full = _report(ScanOptions(), has_ssl=True, ssl_issuer="R3", has_login_form=True)
    dns_only = _report(ScanOptions(http=False), risk_score=20)

    assert compute_diff(full, dns_only).modified_domains == []
    assert compute_diff(dns_only, full).modified_domains == []


def test_diff_says_why_two_scans_are_not_comparable() -> None:
    from otacon.diff import compute_diff

    d = compute_diff(_report(ScanOptions()), _report(ScanOptions(http=False, dnsbl=False)))
    assert len(d.caveats) == 2
    assert any("websites" in c for c in d.caveats)
    assert any("reputation lists" in c for c in d.caveats)


def test_diff_still_reports_real_changes_on_matching_scans() -> None:
    """The guard must not mute a genuine finding between two comparable scans."""
    from otacon.diff import compute_diff

    before = _report(ScanOptions())
    after = _report(ScanOptions(), has_login_form=True, dnsbl_listed=True, dnsbl_source="DBL")

    changes = compute_diff(before, after).modified_domains[0].changes
    assert any("login form" in c for c in changes)
    assert any("DNSBL" in c for c in changes)


def test_diff_always_compares_dns_and_mail() -> None:
    """MX and A records are never gated by a flag, so they stay comparable."""
    from otacon.diff import compute_diff

    before = _report(ScanOptions(http=False))
    after = _report(ScanOptions(), has_mx=True, mx_records=["mx.evil.com"])

    changes = compute_diff(before, after).modified_domains[0].changes
    assert any("Mail server added" in c for c in changes)


# ---------------------------------------------------------------------------
# takedown notice — the defanging must survive the whole template
# ---------------------------------------------------------------------------


def test_the_notice_leaves_no_live_hostname_in_its_prose() -> None:
    """Three raw copies of the domain used to sit in the body, autolinked by mail clients."""
    from otacon.triage.notice import build_takedown_notice

    row = DomainResult(
        domain="examp1e.com",
        kind=PermutationType.HOMOGLYPH,
        resolves=True,
        has_mx=True,
        mx_records=["mail.examp1e.com"],
    )
    notice = build_takedown_notice(row, "example.com")
    prose, _, machine = notice.partition("-- MACHINE-READABLE VALUES")

    assert "examp1e.com" not in prose, "a live hostname is left in the body"
    assert "example.com" not in prose, "the target's own name is left live in the body"
    assert "mail.examp1e.com" not in prose, "an MX hostname is left live in the body"
    assert "examp1e[.]com" in prose

    # The registrar still gets what its tooling needs, in one labelled place.
    assert "domain=examp1e.com" in machine
    assert "target=example.com" in machine


# ---------------------------------------------------------------------------
# health signals: a check that could not run must not read as a clean one
# ---------------------------------------------------------------------------


def test_probe_failures_mark_a_scan_degraded() -> None:
    """A probe that raises returns a blank result, which reads as 'not registered'."""
    rows = [DomainResult(domain=f"e{i}.com", kind=PermutationType.TYPO) for i in range(10)]
    report = ScanReport(target="example.com", results=rows, probe_failures=3)
    assert report.degraded is True
    assert report.probe_failure_ratio == pytest.approx(0.3)


def test_a_handful_of_probe_failures_is_not_degraded() -> None:
    rows = [DomainResult(domain=f"e{i}.com", kind=PermutationType.TYPO) for i in range(100)]
    assert ScanReport(target="example.com", results=rows, probe_failures=1).degraded is False


def test_the_verdict_names_probes_when_probes_are_what_failed() -> None:
    """It used to say 'DNS lookups failed' whatever the cause."""
    from otacon.triage.verdict import verdict

    rows = [DomainResult(domain=f"e{i}.com", kind=PermutationType.TYPO) for i in range(10)]
    v = verdict(
        ScanReport(
            target="example.com",
            total_permutations=10,
            results=rows,
            probe_failures=5,
            dns_queries=20,
            dns_failures=0,
        )
    )
    assert v.degraded is True
    assert "DNS" not in v.headline
    assert "could not be completed" in v.headline


@pytest.mark.asyncio
async def test_a_refused_reputation_list_is_not_a_clean_bill(caplog) -> None:
    """Spamhaus answers 127.255.255.254 to queries via a public resolver."""
    import logging

    from otacon.net.dnsbl import check_dnsbl

    class _Rec:
        def __init__(self, host):
            self.host = host

    class _Refusing:
        async def query_dns(self, name, rtype):
            return [_Rec("127.255.255.254")] if "spamhaus" in name else []

    with caplog.at_level(logging.WARNING, logger="otacon.net.dnsbl"):
        listed, source, refused = await check_dnsbl("evil.com", _Refusing())

    assert (listed, source) == (False, None)
    assert refused is True, "a refusal must be distinguishable from 'not listed'"
    assert "declined" in caplog.text


@pytest.mark.asyncio
async def test_a_real_listing_still_reports_listed() -> None:
    from otacon.net.dnsbl import check_dnsbl

    class _Rec:
        def __init__(self, host):
            self.host = host

    class _Listing:
        async def query_dns(self, name, rtype):
            return [_Rec("127.0.1.4")] if "spamhaus" in name else []

    assert await check_dnsbl("evil.com", _Listing()) == (
        True,
        "Spamhaus DBL (phishing)",
        False,
    )
