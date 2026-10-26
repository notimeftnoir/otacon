"""Tests for enrichment: ASN via Team Cymru, RDAP abuse contacts and registration."""

from __future__ import annotations

import io
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pycares
import pytest
import respx
from rich.console import Console

from otacon import _scanner, enrich
from otacon.models import DomainResult, PermutationType
from otacon.resolver import Resolver

pytestmark = pytest.mark.real_feeds

# Shapes copied from real rdap.org answers (exampel.com, 192.64.151.235).
DOMAIN_RDAP = {
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "DNC Holdings, Inc."]],
            ],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [["fn", {}, "text", ""], ["email", {}, "text", "abuse@directnic.com"]],
                    ],
                }
            ],
        }
    ]
}
IP_RDAP = {
    "entities": [
        {
            "roles": ["registrant"],
            "entities": [
                {
                    "roles": ["administrative", "abuse"],
                    "vcardArray": ["vcard", [["email", {}, "text", "noc@voodoo.example"]]],
                }
            ],
        }
    ]
}


def test_abuse_email_and_registrar_are_found_wherever_nested() -> None:
    assert enrich.registrar_name(DOMAIN_RDAP) == "DNC Holdings, Inc."
    assert enrich.abuse_email(DOMAIN_RDAP) == "abuse@directnic.com"
    assert enrich.abuse_email(IP_RDAP) == "noc@voodoo.example"


def test_malformed_rdap_yields_nothing_instead_of_crashing() -> None:
    for junk in (None, [], {"entities": "x"}, {"entities": [{"roles": None, "vcardArray": [1]}]}):
        assert enrich.abuse_email(junk) is None
        assert enrich.registrar_name(junk) is None


def test_rdap_strings_lose_control_characters() -> None:
    hostile = {
        "entities": [
            {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "a\x1b[2J@x.com"]]]}
        ]
    }
    assert enrich.abuse_email(hostile) == "a[2J@x.com"


@pytest.mark.asyncio
@respx.mock
async def test_takedown_contacts_combines_registrar_and_hosting() -> None:
    respx.get("https://rdap.org/domain/exampel.com").respond(200, json=DOMAIN_RDAP)
    respx.get("https://rdap.org/ip/192.0.2.7").respond(200, json=IP_RDAP)
    async with httpx.AsyncClient() as client:
        contacts = await enrich.takedown_contacts(client, "exampel.com", "192.0.2.7")
    assert contacts == {
        "registrar": "DNC Holdings, Inc.",
        "registrar_abuse": "abuse@directnic.com",
        "hosting_abuse": "noc@voodoo.example",
    }


@pytest.mark.asyncio
@respx.mock
async def test_is_registered_reads_the_registry_status() -> None:
    respx.get("https://rdap.org/domain/taken.com").respond(200, json={})
    respx.get("https://rdap.org/domain/free.com").respond(404)
    respx.get("https://rdap.org/domain/flaky.com").respond(503)
    async with httpx.AsyncClient() as client:
        assert await enrich.is_registered(client, "taken.com") is True
        assert await enrich.is_registered(client, "free.com") is False
        assert await enrich.is_registered(client, "flaky.com") is None


def _txt(records: dict[str, bytes]) -> AsyncMock:
    async def query(name: str, rtype: str) -> MagicMock:
        data = records.get(name)
        answer = [MagicMock(type=pycares.QUERY_TYPE_TXT, data=MagicMock(data=data))] if data else []
        return MagicMock(answer=answer)

    return AsyncMock(side_effect=query)


@pytest.mark.asyncio
async def test_asn_info_for_ipv4_and_caches_the_as_name() -> None:
    zone = {
        "7.2.0.192.origin.asn.cymru.com": b"13335 209242 | 192.0.2.0/24 | US | arin | 2010-07-14",
        "AS13335.asn.cymru.com": (
            b"13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"
        ),
    }
    r = Resolver()
    mock = _txt(zone)
    with patch.object(r._dns, "query_dns", mock):
        first = await r.asn_info("192.0.2.7")
        second = await r.asn_info("192.0.2.7")
    assert first == second == (13335, "CLOUDFLARENET - Cloudflare, Inc., US", "US")
    as_lookups = [c for c in mock.await_args_list if c.args[0].startswith("AS")]
    assert len(as_lookups) == 1


@pytest.mark.asyncio
async def test_asn_info_builds_the_ipv6_nibble_name() -> None:
    r = Resolver()
    mock = _txt({})
    with patch.object(r._dns, "query_dns", mock):
        assert await r.asn_info("2001:db8::1") is None
    asked = mock.await_args_list[0].args[0]
    assert asked.endswith(".origin6.asn.cymru.com")
    assert asked.startswith("1.0.0.0.") and asked.count(".") == 32 + 3


@pytest.mark.asyncio
async def test_asn_info_rejects_garbage() -> None:
    r = Resolver()
    with patch.object(r._dns, "query_dns", _txt({"4.3.2.1.origin.asn.cymru.com": b"NA | x"})):
        assert await r.asn_info("1.2.3.4") is None
    assert await r.asn_info("not-an-ip") is None


class _SilentResolver:
    target_title = None
    target_favicon = None
    dns_hijack_detected = False

    def __init__(self, **_: object) -> None: ...

    async def __aenter__(self) -> _SilentResolver:
        return self

    async def __aexit__(self, *_: object) -> None: ...

    async def mail_posture(self, domain: str) -> tuple[bool, str | None]:
        return True, "reject"

    async def check_one(self, perm) -> DomainResult:  # type: ignore[no-untyped-def]
        return DomainResult(domain=perm.domain, kind=perm.kind, dns_inconclusive=True)


@pytest.mark.asyncio
async def test_scan_settles_dns_silent_variants_with_rdap(monkeypatch) -> None:
    monkeypatch.setattr(_scanner, "Resolver", _SilentResolver)
    monkeypatch.setattr("otacon.intel.load_feeds", AsyncMock(return_value={}))
    monkeypatch.setattr("otacon.ct.recent_certificates", AsyncMock(return_value={}))
    monkeypatch.setattr(_scanner, "_RDAP_SETTLE_MAX", 3)

    verdicts = iter([True, False, None])
    monkeypatch.setattr(
        "otacon.enrich.is_registered", AsyncMock(side_effect=lambda c, d: next(verdicts))
    )
    report = await _scanner.run_scan(
        "example.com", 10, False, Console(file=io.StringIO()), show_progress=False
    )
    settled = report.results  # sorted: the registered one scores above zero
    registered = [r for r in settled if r.rdap_registered]
    assert len(registered) == 1 and registered[0].is_registered
    assert registered[0].kind in PermutationType and registered[0].risk_score > 0
    # One registered, one confirmed free, one still unknown; the rest never asked.
    assert len(report.inconclusive) == len(settled) - 2


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    monkeypatch.setattr(enrich, "_BACKOFF", 0)
    monkeypatch.setattr(enrich, "_MAX_WAIT", 0)


@pytest.mark.asyncio
@respx.mock
async def test_rdap_rides_out_a_rate_limit() -> None:
    route = respx.get("https://rdap.org/domain/busy.com").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "2"}),
            httpx.Response(200, json={}),
        ]
    )
    async with httpx.AsyncClient() as client:
        assert await enrich.is_registered(client, "busy.com") is True
    assert route.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_takedown_contacts_climb_to_the_registered_parent() -> None:
    respx.get("https://rdap.org/domain/example.com.verify.org").respond(400)  # PIR style
    respx.get("https://rdap.org/domain/com.verify.org").respond(404)
    respx.get("https://rdap.org/domain/verify.org").respond(200, json=DOMAIN_RDAP)
    async with httpx.AsyncClient() as client:
        contacts = await enrich.takedown_contacts(client, "example.com.verify.org", None)
    assert contacts["registrar_abuse"] == "abuse@directnic.com"
