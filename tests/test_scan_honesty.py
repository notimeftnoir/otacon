"""A scan must not claim to know what it never checked.

Every case here is a place where silence used to read as an all-clear: a
lookup that could not run, a probe that raised, a reputation list that refused
to answer, a CI gate that exited 0 on a scan that saw nothing.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from otacon.cli import app
from otacon.core.models import DomainResult, ScanOptions, ScanReport
from otacon.core.types import PermutationType


@pytest.mark.asyncio
async def test_a_fresh_report_defaults_to_a_full_scan() -> None:
    """ScanOptions defaults keep a report stored before this field reading as it did."""
    restored = ScanReport.model_validate_json(ScanReport(target="example.com").model_dump_json())
    assert restored.options == ScanOptions(http=True, whois=True, dnsbl=True, ct=True)


def test_a_report_without_an_options_field_still_loads() -> None:
    """Reports written before 4.0.0 have no `options` key; they must not fail to open."""
    legacy = '{"target":"example.com","started_at":"2026-01-01T00:00:00Z","results":[]}'
    assert ScanReport.model_validate_json(legacy).options == ScanOptions()


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


def test_probe_failures_mark_a_scan_degraded() -> None:
    """A probe that raises returns a blank result, which reads as 'not registered'."""
    rows = [DomainResult(domain=f"e{i}.com", kind=PermutationType.TYPO) for i in range(10)]
    report = ScanReport(target="example.com", results=rows, probe_failures=3)
    assert report.degraded is True
    assert report.probe_failure_ratio == pytest.approx(0.3)


def test_a_handful_of_probe_failures_is_not_degraded() -> None:
    rows = [DomainResult(domain=f"e{i}.com", kind=PermutationType.TYPO) for i in range(100)]
    assert ScanReport(target="example.com", results=rows, probe_failures=1).degraded is False


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


@pytest.mark.asyncio
async def test_a_null_mx_is_not_mail_capability(monkeypatch) -> None:
    """`MX 0 .` says this domain handles no mail. It used to earn +25 for the
    opposite.

    Found by running a real scan: example.net topped the table at 70/100, and
    +25 of that was "has an MX record — ready for email phishing" — on a domain
    publishing a null MX, `v=spf1 -all` and `p=reject`. c-ares reports the root
    exchange as an empty string, so it arrived looking like a parse failure and
    `bool(mx)` was True for a list of one blank.
    """
    import otacon.net.resolver as resolver_mod
    from otacon.core.models import Permutation

    class _Rec:
        host = ""  # exactly what c-ares gives for `MX 0 .`

    async def one_null_mx(self, domain, rtype):
        return [_Rec()] if rtype == "MX" else []

    monkeypatch.setattr(resolver_mod.Resolver, "_query", one_null_mx)
    r = resolver_mod.Resolver(check_http=False, check_whois=False, check_dnsbl=False)
    result = await r.check_one(Permutation(domain="example.net", kind=PermutationType.TLD_SWAP))

    assert result.mx_records == ["."], "the published record must survive, readable"
    assert result.has_mx is False, "a null MX is not a mail server"
    assert result.is_registered is True, "publishing any MX still proves registration"


@pytest.mark.asyncio
async def test_a_real_mx_still_counts(monkeypatch) -> None:
    """The guard must not cost a genuine mail exchange its points."""
    import otacon.net.resolver as resolver_mod
    from otacon.core.models import Permutation

    class _Rec:
        host = "mx1.evil.example"

    async def one_real_mx(self, domain, rtype):
        return [_Rec()] if rtype == "MX" else []

    monkeypatch.setattr(resolver_mod.Resolver, "_query", one_real_mx)
    r = resolver_mod.Resolver(check_http=False, check_whois=False, check_dnsbl=False)
    result = await r.check_one(Permutation(domain="evil.example", kind=PermutationType.TYPO))

    assert result.has_mx is True
    assert result.mx_records == ["mx1.evil.example"]


def test_a_null_mx_earns_no_phishing_points() -> None:
    """End of the chain: the scoring engine must not pay out for it."""
    from otacon.scoring.engine import score

    null_mx = score(
        DomainResult(
            domain="example.net",
            kind=PermutationType.TLD_SWAP,
            resolves=True,
            mx_records=["."],
            has_mx=False,
        ),
        "example.com",
    )
    real_mx = score(
        DomainResult(
            domain="examp1e.com",
            kind=PermutationType.HOMOGLYPH,
            resolves=True,
            mx_records=["mx1.evil.example"],
            has_mx=True,
        ),
        "example.com",
    )
    assert not any("email phishing" in why for why in null_mx.risk_reasons)
    assert any("email phishing" in why for why in real_mx.risk_reasons)
    assert null_mx.is_registered, "it is still a registered domain"


# ---------------------------------------------------------------------------
# the CI gate: "nothing found" is only an answer when the scan could look
# ---------------------------------------------------------------------------


def _gate(monkeypatch, report: ScanReport, *args: str) -> int:
    async def fake_run_scan(domain, concurrency, check_http, **kwargs):
        return report

    monkeypatch.setattr("otacon.cli._run_scan", fake_run_scan)
    return CliRunner().invoke(app, ["-q", "scan", "example.com", *args]).exit_code


_DEGRADED = ScanReport(
    target="example.com", total_permutations=500, dns_queries=1000, dns_failures=1000
)


def test_fail_on_exits_3_when_dns_never_answered(monkeypatch) -> None:
    """The audit's reproduction: 100% DNS failure used to exit 0 under --fail-on low."""
    assert _gate(monkeypatch, _DEGRADED, "--fail-on", "low") == 3


def test_fail_on_exits_3_when_the_reputation_list_refused(monkeypatch) -> None:
    refused = ScanReport(target="example.com", total_permutations=10, dnsbl_refused=True)
    assert _gate(monkeypatch, refused, "--fail-on", "high") == 3


def test_fail_on_still_exits_0_on_a_clean_healthy_scan(monkeypatch) -> None:
    healthy = ScanReport(target="example.com", total_permutations=10, dns_queries=40)
    assert _gate(monkeypatch, healthy, "--fail-on", "high") == 0


def test_a_breach_wins_over_an_unverified_scan(monkeypatch) -> None:
    """A finding is a finding even on a degraded run: 2, not 3."""
    from otacon.core.types import RiskLevel

    hit = DomainResult(
        domain="examp1e.com",
        kind=PermutationType.HOMOGLYPH,
        resolves=True,
        risk_level=RiskLevel.HIGH,
    )
    report = ScanReport(
        target="example.com",
        total_permutations=10,
        results=[hit],
        dns_queries=10,
        dns_failures=10,
    )
    assert _gate(monkeypatch, report, "--fail-on", "high") == 2


def test_without_fail_on_a_degraded_scan_keeps_exit_0(monkeypatch) -> None:
    """Exit 3 is part of the --fail-on contract only; a plain scan still exits 0."""
    assert _gate(monkeypatch, _DEGRADED) == 0


def test_the_json_report_says_whether_it_can_be_trusted() -> None:
    """`degraded` was a property, so asdict() dropped it from every --json report."""
    assert json.loads(_DEGRADED.model_dump_json())["degraded"] is True
    assert json.loads(ScanReport(target="example.com").model_dump_json())["degraded"] is False


def test_degraded_is_recomputed_on_load_not_trusted_from_disk() -> None:
    forged = json.loads(_DEGRADED.model_dump_json())
    forged["degraded"] = False
    assert ScanReport.model_validate(forged).degraded is True


# ---------------------------------------------------------------------------
# resolver health counters reach every record type
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mx_and_txt_failures_count_towards_degraded(monkeypatch) -> None:
    """MX, NS and TXT used to swallow their own errors without counting them."""
    import otacon.net.resolver as resolver_mod

    async def broken(resolver, name, rtype):
        raise TimeoutError

    monkeypatch.setattr(resolver_mod, "_query_dns", broken)
    r = resolver_mod.Resolver(check_http=False, check_whois=False, check_dnsbl=False)
    assert await r._resolve_mx("example.com") == []
    assert await r._resolve_txt("example.com") == []
    assert (r.dns_queries, r.dns_failures) == (2, 2)


@pytest.mark.asyncio
async def test_a_probe_that_raises_is_counted(monkeypatch) -> None:
    import otacon.net.resolver as resolver_mod
    from otacon.core.models import Permutation

    async def boom(self, domain):
        raise RuntimeError("library break")

    monkeypatch.setattr(resolver_mod.Resolver, "_resolve_a", boom)
    r = resolver_mod.Resolver(check_http=False, check_whois=False, check_dnsbl=False)
    result = await r.check_one(Permutation(domain="examp1e.com", kind=PermutationType.TYPO))
    assert result.is_registered is False
    assert r.probe_failures == 1


@pytest.mark.asyncio
async def test_one_refusal_marks_the_whole_scan(monkeypatch) -> None:
    import otacon.net.resolver as resolver_mod

    async def refused(domain, resolver, timeout):
        return False, None, True

    monkeypatch.setattr(resolver_mod, "check_dnsbl", refused)
    r = resolver_mod.Resolver(check_http=False)
    assert await r._check_dnsbl("evil.com") == (False, None)
    assert r.dnsbl_refused is True


# ---------------------------------------------------------------------------
# re-probing one row honours what the operator switched off
# ---------------------------------------------------------------------------


def test_rescan_carries_the_scans_options(monkeypatch) -> None:
    """A row from a --no-whois --no-dnsbl scan must not query a registry or a blocklist."""
    from rich.console import Console

    import otacon.triage.actions as actions

    seen: list[dict[str, bool]] = []

    class _Spy:
        target_title = None

        def __init__(self, check_http, target, check_whois=True, check_dnsbl=True):
            seen.append({"http": check_http, "whois": check_whois, "dnsbl": check_dnsbl})

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def check_one(self, perm):
            return DomainResult(domain=perm.domain, kind=perm.kind, resolves=True)

    # Patched where _get_inter looks first, as the rest of the suite does.
    monkeypatch.setattr("otacon.interactive.Resolver", _Spy, raising=False)
    monkeypatch.setattr(actions, "Resolver", _Spy)
    row = DomainResult(domain="examp1e.com", kind=PermutationType.HOMOGLYPH)
    opts = ScanOptions(http=True, whois=False, dnsbl=False)
    updated = actions._rescan_result(row, "example.com", True, Console(quiet=True), opts)

    assert seen == [{"http": True, "whois": False, "dnsbl": False}]
    assert updated.resolves is True


# ---------------------------------------------------------------------------
# takedown notice: the defanging must survive the whole template
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
