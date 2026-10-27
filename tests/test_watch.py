"""Tests for `otacon watch`: change detection, state, alerts and the CLI flow."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from typer.testing import CliRunner

from otacon import watch
from otacon.cli import app
from otacon.models import Discovery, DomainResult, PermutationType, ScanReport
from otacon.theme import RiskLevel


def _r(domain: str, score: int, level: RiskLevel, **kw: object) -> DomainResult:
    return DomainResult(
        domain=domain,
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=score,
        risk_level=level,
        **kw,  # type: ignore[arg-type]
    )


def _report(*results: DomainResult, discovered: tuple[str, ...] = ()) -> ScanReport:
    return ScanReport(
        target="example.com",
        results=list(results),
        discovered=[Discovery(host=h, sources=["OpenPhish"]) for h in discovered],
    )


@pytest.fixture
def store(tmp_path):
    s = watch.State(tmp_path / "w.sqlite")
    yield s
    s.close()


def test_first_run_is_a_baseline_and_then_nothing_changed(store) -> None:
    report = _report(_r("exampel.com", 40, RiskLevel.MEDIUM), discovered=("a.example-x.com",))
    assert not store.has_baseline("example.com")
    store.save(report)
    assert store.has_baseline("example.com")
    assert store.diff(report) == []


def test_new_and_discovered_alert_at_once(store) -> None:
    store.save(_report(_r("exampel.com", 40, RiskLevel.MEDIUM), discovered=("old.example-x.com",)))
    later = _report(
        _r("exampel.com", 40, RiskLevel.MEDIUM),
        _r("examp1e.com", 70, RiskLevel.HIGH),
        discovered=("old.example-x.com", "new.example-x.com"),
    )
    assert {(e.kind, e.domain) for e in store.diff(later)} == {
        ("new", "examp1e.com"),
        ("discovered", "new.example-x.com"),
    }


def test_probe_signals_escalate_only_when_seen_twice_in_a_row(store) -> None:
    quiet = _report(_r("exampel.com", 40, RiskLevel.MEDIUM))
    live = _report(_r("exampel.com", 85, RiskLevel.CRITICAL, has_mx=True, http_status=200))
    store.save(quiet)
    assert store.diff(live) == []  # first sighting: could be a probe fluke
    store.save(live)
    [event] = store.diff(live)  # second run in a row: real
    assert event.kind == "escalated"
    assert "mail server added" in event.detail and "website went live" in event.detail
    store.save(live)
    assert store.diff(live) == []  # confirmed signals are remembered


def test_reliable_signals_escalate_at_once(store) -> None:
    store.save(_report(DomainResult(domain="exampel.com", kind=PermutationType.TYPO, has_mx=True)))
    reported = _report(_r("exampel.com", 90, RiskLevel.CRITICAL, intel_sources=["OpenPhish"]))
    [event] = store.diff(reported)
    assert "now resolves" in event.detail and "reported as phishing" in event.detail


def test_gone_needs_two_misses_in_a_row_and_dns_silence_never_counts(store) -> None:
    both = _report(_r("a.com", 40, RiskLevel.MEDIUM), _r("b.com", 40, RiskLevel.MEDIUM))
    silent_b = _report(
        DomainResult(domain="b.com", kind=PermutationType.TYPO, dns_inconclusive=True)
    )
    store.save(both)
    assert store.diff(silent_b) == []  # a.com: first miss; b.com: silent
    store.save(silent_b)
    assert [(e.kind, e.domain) for e in store.diff(silent_b)] == [("gone", "a.com")]
    store.save(silent_b)
    # a.com was forgotten after being reported gone; b.com never left.
    assert [(e.kind, e.domain) for e in store.diff(both)] == [("new", "a.com")]


def test_flapping_signals_and_one_off_misses_raise_nothing(store) -> None:
    full = _report(_r("exampel.com", 70, RiskLevel.HIGH, has_mx=True, has_ssl=True))
    flapped = _report(_r("exampel.com", 45, RiskLevel.MEDIUM))
    store.save(full)
    store.save(flapped)  # MX and TLS probe failed this run
    assert store.diff(full) == []  # they are back: nothing new happened
    store.save(_report())  # the whole variant missed one run
    assert store.diff(full) == []


def test_summary_defangs_every_domain() -> None:
    text = watch.summary("example.com", [watch.Event("new", "exampel.com", "registered")])
    assert "example[.]com" in text and "exampel[.]com" in text
    assert "exampel.com" not in text


@pytest.mark.parametrize(
    ("url", "key"),
    [
        ("https://discord.com/api/webhooks/1/x", "content"),
        ("https://hooks.slack.com/services/T/B/x", "text"),
        ("https://contoso.webhook.office.com/webhookb2/x", "text"),
        ("https://siem.example/ingest", "events"),
    ],
)
def test_payload_matches_the_service(url: str, key: str) -> None:
    body = watch._payload(url, "example.com", [watch.Event("new", "exampel.com", "x")])
    assert key in body


@pytest.mark.asyncio
@respx.mock
async def test_notify_reports_delivery() -> None:
    respx.post("https://ok.example/hook").respond(204)
    respx.post("https://down.example/hook").mock(side_effect=httpx.ConnectError("x"))
    events = [watch.Event("new", "exampel.com", "x")]
    async with httpx.AsyncClient() as client:
        assert await watch.notify(client, "https://ok.example/hook", "example.com", events)
        assert not await watch.notify(client, "https://down.example/hook", "example.com", events)


@respx.mock
def test_cli_baseline_then_alert_and_exit_code(tmp_path, monkeypatch) -> None:
    reports = iter(
        [
            _report(_r("exampel.com", 40, RiskLevel.MEDIUM)),
            _report(
                _r("exampel.com", 40, RiskLevel.MEDIUM), _r("examp1e.com", 90, RiskLevel.CRITICAL)
            ),
        ]
    )

    async def fake_run_scan(target, concurrency, check_http, **kw):
        return next(reports)

    monkeypatch.setattr("otacon.cli._run_scan", fake_run_scan)
    hook = respx.post("https://hooks.slack.com/services/T/B/x").respond(200)
    args = ["watch", "example.com", "--state", str(tmp_path / "w.sqlite"), "--exit-code"]
    monkeypatch.setenv("OTACON_WEBHOOK", "https://hooks.slack.com/services/T/B/x")

    first = CliRunner().invoke(app, args)
    assert first.exit_code == 0 and "Baseline saved" in first.output
    assert not hook.called

    second = CliRunner().invoke(app, ["-q", *args])
    assert second.exit_code == 2
    assert json.loads(second.output)["example.com"][0]["domain"] == "examp1e.com"
    assert "examp1e[.]com" in json.loads(hook.calls.last.request.content)["text"]


def test_cli_rejects_an_invalid_domain(tmp_path) -> None:
    result = CliRunner().invoke(app, ["watch", "not a domain", "--state", str(tmp_path / "w")])
    assert result.exit_code == 1


def test_cli_ignores_an_empty_webhook_variable(tmp_path, monkeypatch) -> None:
    reports = iter([_report(), _report(_r("examp1e.com", 90, RiskLevel.CRITICAL))])

    async def fake_run_scan(target, concurrency, check_http, **kw):
        return next(reports)

    monkeypatch.setattr("otacon.cli._run_scan", fake_run_scan)
    monkeypatch.setenv("OTACON_WEBHOOK", "")
    args = ["watch", "example.com", "--state", str(tmp_path / "w.sqlite")]
    assert CliRunner().invoke(app, args).exit_code == 0
    second = CliRunner().invoke(app, args)
    assert second.exit_code == 0 and "Webhooks" not in second.output
