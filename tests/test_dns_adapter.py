"""Regression tests for the aiodns>=4 DNSResult shape.

The pre-existing suite only ever fed the resolver pre-4.0 lists, so the real
aiodns 4 return type (DNSResult) went untested and every lookup silently failed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from otacon.net.dns import query_records


@dataclass
class _Data:
    addr: str | None = None
    exchange: str | None = None
    nsdname: str | None = None
    data: bytes | None = None
    priority: int | None = None


@dataclass
class _Rec:
    data: Any
    ttl: int = 60


@dataclass
class _DNSResult:
    """Mirrors pycares.DNSResult: records live under .answer, not by iteration."""

    answer: list[_Rec]

    def __iter__(self) -> Any:
        raise TypeError("'DNSResult' object is not iterable")


class _Modern:
    """An aiodns>=4 style resolver: query_dns only, DNSResult return."""

    def __init__(self, result: _DNSResult) -> None:
        self._result = result

    async def query_dns(self, name: str, rtype: str) -> _DNSResult:
        return self._result


class _Legacy:
    """A pre-4.0 style resolver: query only, flat list return."""

    def __init__(self, records: list[Any]) -> None:
        self._records = records

    async def query(self, name: str, rtype: str) -> list[Any]:
        return self._records


@pytest.mark.asyncio
async def test_query_records_unwraps_dnsresult_a() -> None:
    res = _DNSResult([_Rec(_Data(addr="93.184.216.34"))])
    records = await query_records(_Modern(res), "example.com", "A")
    assert [r.host for r in records] == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_query_records_unwraps_mx_and_ns() -> None:
    mx = _DNSResult([_Rec(_Data(exchange="mail.example.com", priority=10))])
    assert [r.host for r in await query_records(_Modern(mx), "example.com", "MX")] == [
        "mail.example.com"
    ]
    ns = _DNSResult([_Rec(_Data(nsdname="ns1.example.com"))])
    assert [r.host for r in await query_records(_Modern(ns), "example.com", "NS")] == [
        "ns1.example.com"
    ]


@pytest.mark.asyncio
async def test_query_records_decodes_txt_bytes() -> None:
    txt = _DNSResult([_Rec(_Data(data=b"v=spf1 -all"))])
    records = await query_records(_Modern(txt), "example.com", "TXT")
    assert [r.text for r in records] == ["v=spf1 -all"]


@pytest.mark.asyncio
async def test_query_records_still_accepts_legacy_lists() -> None:
    class _Old:
        host = "1.2.3.4"

    records = await query_records(_Legacy([_Old()]), "example.com", "A")
    assert [r.host for r in records] == ["1.2.3.4"]


# --------------------------------------------------------------------------
# Live resolver check. Excluded by default (`-m 'not network'`); run with
# `pytest -m network`. This is the test whose absence let the aiodns 4 break
# ship: every other DNS test injects a fake record shape, so a change to the
# library's real return type is invisible to them.
# --------------------------------------------------------------------------


@pytest.mark.network
@pytest.mark.asyncio
async def test_live_resolver_returns_records_against_real_aiodns() -> None:
    import aiodns

    resolver = aiodns.DNSResolver(timeout=5.0, tries=2)

    a_records = await query_records(resolver, "example.com", "A")
    assert a_records, "example.com must return at least one A record"
    assert all(r.host for r in a_records), "A records must expose a non-empty .host"

    ns_records = await query_records(resolver, "example.com", "NS")
    assert ns_records, "example.com must return NS records"
    assert all("." in r.host for r in ns_records)

    txt_records = await query_records(resolver, "example.com", "TXT")
    assert all(isinstance(r.text, str) for r in txt_records)


@pytest.mark.network
@pytest.mark.asyncio
async def test_live_scan_finds_registered_lookalikes() -> None:
    """End-to-end guard: a scan of a heavily squatted brand must not come back empty.

    v2.0.0 reported "nothing registered" for all 280 github.com lookalikes because
    the DNS TypeError was swallowed by graceful degradation. An all-clear verdict is
    indistinguishable from a broken resolver without an assertion like this one.
    """
    from rich.console import Console

    from otacon.engine.scanner import run_scan

    report = await run_scan(
        target="github.com",
        concurrency=50,
        check_http=False,
        console=Console(quiet=True),
        show_progress=False,
        check_whois=False,
        check_dnsbl=False,
        check_ct=False,
    )
    registered = [r for r in report.results if r.resolves]
    assert len(registered) > 20, f"only {len(registered)} of {len(report.results)} resolved"
