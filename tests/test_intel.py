"""Tests for threat-intel feeds: parsing, local matching, caching, URLhaus opt-in."""

from __future__ import annotations

import os
import time

import httpx
import pytest
import respx

from otacon import intel, scoring
from otacon.models import DomainResult, PermutationType

pytestmark = pytest.mark.real_feeds

OPENPHISH = intel._FEEDS["OpenPhish"]
ARMY = intel._FEEDS["Phishing Army"]


def test_host_parses_urls_bare_domains_and_skips_comments() -> None:
    assert intel._host("https://WWW.Evil-Example.com/login?x=1") == "evil-example.com"
    assert intel._host("evil-example.net/path") == "evil-example.net"
    assert intel._host("# comment") is None
    assert intel._host("   ") is None


def test_match_finds_the_domain_itself_and_phishing_on_its_subdomains() -> None:
    feeds = {
        "A": frozenset({"exampel.com", "login.example-secure.com", "unrelated.org"}),
        "B": frozenset({"exampel.com"}),
    }
    hits = intel.match(["exampel.com", "example-secure.com", "examp1e.com"], feeds)
    assert hits == {"exampel.com": ["A", "B"], "example-secure.com": ["A"]}


def test_match_does_not_treat_a_shared_suffix_as_a_subdomain() -> None:
    feeds = {"A": frozenset({"notexampel.com"})}
    assert intel.match(["exampel.com"], feeds) == {}


@pytest.mark.asyncio
@respx.mock
async def test_load_feeds_downloads_then_serves_from_cache(tmp_path) -> None:
    op = respx.get(OPENPHISH).respond(200, text="https://exampel.com/a\n")
    respx.get(ARMY).respond(200, text="# list\nexamp1e.com\n")
    async with httpx.AsyncClient() as client:
        first = await intel.load_feeds(client, tmp_path)
        second = await intel.load_feeds(client, tmp_path)
    assert first == {"OpenPhish": {"exampel.com"}, "Phishing Army": {"examp1e.com"}}
    assert second == first
    assert op.call_count == 1  # second load came from the cache


@pytest.mark.asyncio
@respx.mock
async def test_load_feeds_falls_back_to_a_stale_cache_when_offline(tmp_path) -> None:
    stale = tmp_path / "openphish.txt"
    stale.write_text("https://exampel.com/\n", encoding="utf-8")
    old = time.time() - intel._TTL - 60
    os.utime(stale, (old, old))
    respx.get(OPENPHISH).mock(side_effect=httpx.ConnectError("offline"))
    respx.get(ARMY).mock(side_effect=httpx.ConnectError("offline"))
    async with httpx.AsyncClient() as client:
        feeds = await intel.load_feeds(client, tmp_path)
    assert feeds == {"OpenPhish": {"exampel.com"}, "Phishing Army": frozenset()}


@pytest.mark.asyncio
@respx.mock
async def test_load_feeds_refuses_an_oversized_feed(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(intel, "_MAX_FEED_BYTES", 10)
    respx.get(OPENPHISH).respond(200, text="x" * 100)
    respx.get(ARMY).respond(200, text="a.com\n")
    async with httpx.AsyncClient() as client:
        feeds = await intel.load_feeds(client, tmp_path)
    assert feeds["OpenPhish"] == frozenset()
    assert not (tmp_path / "openphish.txt").exists()


@pytest.mark.asyncio
@respx.mock
async def test_urlhaus_sends_the_key_and_reads_query_status() -> None:
    route = respx.post(intel._URLHAUS_API).respond(200, json={"query_status": "ok"})
    async with httpx.AsyncClient() as client:
        assert await intel.urlhaus_listed(client, "exampel.com", "k3y")
    assert route.calls.last.request.headers["Auth-Key"] == "k3y"


@pytest.mark.asyncio
@respx.mock
async def test_urlhaus_treats_errors_and_odd_json_as_not_listed() -> None:
    respx.post(intel._URLHAUS_API).respond(200, json=["not", "a", "dict"])
    async with httpx.AsyncClient() as client:
        assert not await intel.urlhaus_listed(client, "exampel.com", "k3y")


def test_intel_listing_scores_high_and_survives_a_redirect_home() -> None:
    r = DomainResult(
        domain="exampel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        http_status=302,
        redirects_to="https://example.com/",
        intel_sources=["OpenPhish"],
    )
    scored = scoring.score(r, "example.com")
    assert not scored.is_likely_defensive
    assert any("reported as phishing by OpenPhish" in x for x in scored.risk_reasons)
    assert scored.risk_score >= 60


def test_host_rejects_names_with_characters_dns_never_uses() -> None:
    assert intel._host("evil\x1b[2J.example.com") is None
    assert intel._host("[link=x]evil.com") is None
    assert intel._host("http://[::1") is None  # malformed URL in a feed


def test_mentions_finds_the_brand_hung_off_throwaway_domains() -> None:
    feeds = {
        "A": frozenset(
            {
                "allegro.id-23843.click",
                "allegrolokalnie.pl-94129.sbs",
                "pl-allegro-pay.shop",
                "unrelated.example",
                "allegro.pl",
                "pay.allegro.pl",
            }
        )
    }
    found = intel.mentions("allegro", feeds, "allegro.pl")
    assert set(found) == {
        "allegro.id-23843.click",
        "allegrolokalnie.pl-94129.sbs",
        "pl-allegro-pay.shop",
    }  # the brand's own domain and subdomains are never reported


def test_mentions_short_brand_needs_a_whole_token_or_prefix() -> None:
    feeds = {"A": frozenset({"login.example.com", "de-ing.web.app", "ingbank.top"})}
    assert set(intel.mentions("ing", feeds, "ing.pl")) == {"de-ing.web.app", "ingbank.top"}


def test_brand_label_is_plain_ascii() -> None:
    from otacon.permutations import brand_label

    assert brand_label("example.co.uk") == "example"
    assert brand_label("xn--abka-99a.pl") == "zabka"
