"""Tests for Certificate Transparency discovery via crt.sh."""

from __future__ import annotations

import io
import os
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from rich.console import Console

from otacon import _scanner, ct
from otacon.models import DomainResult

pytestmark = pytest.mark.real_feeds

NOW = datetime.now(UTC)


def _row(names: str, days_ago: int) -> dict[str, object]:
    issued = (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S")
    return {"name_value": names, "not_before": issued, "issuer_name": "C=US, O=Let's Encrypt"}


def test_names_keeps_recent_brand_hosts_and_their_first_issue_date() -> None:
    rows = [
        _row("*.allegro-pay-secure.com\nallegro-pay-secure.com", 3),
        _row("allegro-pay-secure.com", 10),  # an older certificate for the same name
        _row("allegro.pl\npay.allegro.pl", 1),  # the brand itself: never reported
        _row("allegro-old-shop.com", 400),  # outside the window
        _row("unrelated.com", 1),
        {"name_value": "allegro-bad-row.com"},  # no not_before: skipped
        "not a dict",
    ]
    found = ct._names(rows, "allegro", "allegro.pl", NOW - timedelta(days=30))
    assert set(found) == {"allegro-pay-secure.com"}
    assert (NOW - found["allegro-pay-secure.com"]).days == 10


def test_names_tolerates_a_non_list_answer() -> None:
    assert ct._names({"error": "x"}, "allegro", "allegro.pl", NOW) == {}


@pytest.mark.asyncio
@respx.mock
async def test_retries_a_502_then_caches_the_answer(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ct, "_BACKOFF", 0)
    route = respx.get(host="crt.sh").mock(
        side_effect=[httpx.Response(502), httpx.Response(200, json=[_row("allegro-x.com", 2)])]
    )
    async with httpx.AsyncClient() as client:
        first = await ct.recent_certificates(client, "allegro", "allegro.pl", root=tmp_path)
        again = await ct.recent_certificates(client, "allegro", "allegro.pl", root=tmp_path)
    assert set(first or {}) == {"allegro-x.com"}
    assert again == first
    assert route.call_count == 2  # one 502 + one success; the second call hit the cache
    assert route.calls[1].request.url.params["q"] == "allegro"


@pytest.mark.asyncio
@respx.mock
async def test_unreachable_without_cache_is_none_not_empty(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ct, "_BACKOFF", 0)
    route = respx.get(host="crt.sh").respond(502)
    async with httpx.AsyncClient() as client:
        assert await ct.recent_certificates(client, "allegro", "allegro.pl", root=tmp_path) is None
    assert route.call_count == ct._RETRIES + 1


@pytest.mark.asyncio
@respx.mock
async def test_unreachable_falls_back_to_a_stale_cache(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ct, "_BACKOFF", 0)
    cached = tmp_path / "ct-allegro.json"
    cached.write_text(
        f'[{{"name_value": "allegro-y.com", "not_before": '
        f'"{(NOW - timedelta(days=1)):%Y-%m-%dT%H:%M:%S}"}}]',
        encoding="utf-8",
    )
    old = time.time() - ct._TTL - 60
    os.utime(cached, (old, old))
    respx.get(host="crt.sh").mock(side_effect=httpx.ConnectError("down"))
    async with httpx.AsyncClient() as client:
        found = await ct.recent_certificates(client, "allegro", "allegro.pl", root=tmp_path)
    assert set(found or {}) == {"allegro-y.com"}


class _QuietResolver:
    """Resolver stand-in: every variant unregistered, no network."""

    target_title = None
    target_favicon = None
    dns_hijack_detected = False

    def __init__(self, **_: object) -> None: ...

    async def __aenter__(self) -> _QuietResolver:
        return self

    async def __aexit__(self, *_: object) -> None: ...

    async def mail_posture(self, domain: str) -> tuple[bool, str | None]:
        return True, "reject"

    async def check_one(self, perm) -> DomainResult:  # type: ignore[no-untyped-def]
        return DomainResult(domain=perm.domain, kind=perm.kind)


async def _scan(monkeypatch, certs: dict[str, datetime] | None):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(_scanner, "Resolver", _QuietResolver)
    monkeypatch.setattr("otacon.intel.load_feeds", AsyncMock(return_value={}))
    monkeypatch.setattr("otacon.ct.recent_certificates", AsyncMock(return_value=certs))
    out = io.StringIO()
    report = await _scanner.run_scan(
        "allegro.pl", 10, False, Console(file=out, width=200), show_progress=False
    )
    return report, out.getvalue()


@pytest.mark.asyncio
async def test_scan_reports_ct_finds_as_discoveries(monkeypatch) -> None:
    issued = NOW - timedelta(days=2)
    report, out = await _scan(monkeypatch, {"allegro-pay-secure.com": issued})
    assert report.ct_available is True
    [found] = report.discovered
    assert (found.host, found.sources, found.first_seen) == (
        "allegro-pay-secure.com",
        ["CT"],
        issued,
    )
    assert "new certificate name(s)" in out


@pytest.mark.asyncio
async def test_scan_says_when_crtsh_was_unreachable(monkeypatch) -> None:
    report, out = await _scan(monkeypatch, None)
    assert report.ct_available is False
    assert "crt.sh) was unreachable" in out


@pytest.mark.asyncio
async def test_whitelist_hides_the_brands_own_other_domains(monkeypatch) -> None:
    monkeypatch.setattr(_scanner, "Resolver", _QuietResolver)
    monkeypatch.setattr("otacon.intel.load_feeds", AsyncMock(return_value={}))
    certs = {"adx.rtb.allegrogroup.com": NOW, "allegro-pay-secure.com": NOW}
    monkeypatch.setattr("otacon.ct.recent_certificates", AsyncMock(return_value=certs))
    report = await _scanner.run_scan(
        "allegro.pl",
        10,
        False,
        Console(file=io.StringIO()),
        exclude={"allegrogroup.com"},
        show_progress=False,
    )
    assert [d.host for d in report.discovered] == ["allegro-pay-secure.com"]
