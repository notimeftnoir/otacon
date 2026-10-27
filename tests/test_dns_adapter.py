"""Regression tests for the aiodns>=4 DNSResult shape.

The pre-existing suite only ever fed the resolver pre-4.0 lists, so the real
aiodns 4 return type (DNSResult) went untested and every lookup silently failed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from otacon.net.dns import DNSClient, query_records


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


@pytest.mark.asyncio
async def test_dnsclient_resolves_through_modern_resolver() -> None:
    client = DNSClient()
    client._resolver = _Modern(  # type: ignore[assignment]
        _DNSResult([_Rec(_Data(addr="93.184.216.34"))])
    )
    assert await client.query_ips("example.com", "A") == ["93.184.216.34"]
