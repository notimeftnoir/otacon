"""Tests for resolver helpers (page title parsing, WHOIS dedup)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from otacon.models import Permutation, PermutationType
from otacon.resolver import _MAX_BODY_BYTES, Resolver, _parse_title


def test_parse_title_basic():
    html = "<html><head><title>Example Domain</title></head></html>"
    assert _parse_title(html) == "Example Domain"


def test_parse_title_with_attrs():
    html = '<title lang="en">Welcome Back</title>'
    assert _parse_title(html) == "Welcome Back"


def test_parse_title_collapses_whitespace():
    html = "<title>  Hello   World  </title>"
    assert _parse_title(html) == "Hello World"


def test_parse_title_truncates_to_80():
    long_title = "A" * 100
    html = f"<title>{long_title}</title>"
    result = _parse_title(html)
    assert result is not None
    assert len(result) == 80


def test_parse_title_missing_returns_none():
    html = "<html><head></head><body>No title here</body></html>"
    assert _parse_title(html) is None


def test_parse_title_empty_tag_returns_none():
    html = "<title></title>"
    assert _parse_title(html) is None


def test_parse_title_case_insensitive():
    html = "<TITLE>Uppercase Tag</TITLE>"
    assert _parse_title(html) == "Uppercase Tag"


def test_parse_title_multiline():
    html = "<title>\n  Phishing Page\n</title>"
    assert _parse_title(html) == "Phishing Page"


def test_parse_title_unescapes_html_entities():
    assert _parse_title("<title>Tom &amp; Jerry</title>") == "Tom & Jerry"
    assert _parse_title("<title>Page &#8211; Subtitle</title>") == "Page – Subtitle"


# ---------------------------------------------------------------------------
# Body cap — a hostile server can't OOM the scanner with a giant/bomb body
# ---------------------------------------------------------------------------

class _FakeStreamResp:
    """Minimal stand-in for httpx.Response.aiter_bytes — counts bytes produced."""

    def __init__(self, total: int, chunk_size: int = 8192) -> None:
        self._total = total
        self._chunk_size = chunk_size
        self.produced = 0

    async def aiter_bytes(self):
        while self.produced < self._total:
            n = min(self._chunk_size, self._total - self.produced)
            self.produced += n
            yield b"a" * n


@pytest.mark.asyncio
async def test_read_capped_stops_at_limit():
    # 50 MB "body" — _read_capped must return <= cap and stop pulling early
    # (never materialising the whole thing, as with a decompression bomb).
    resp = _FakeStreamResp(50 * 1024 * 1024)
    text = await Resolver._read_capped(resp)
    assert len(text.encode("utf-8")) <= _MAX_BODY_BYTES
    # Generation halted shortly after the cap, not after the full 50 MB.
    assert resp.produced < _MAX_BODY_BYTES + resp._chunk_size


@pytest.mark.asyncio
async def test_read_capped_small_body_intact():
    resp = _FakeStreamResp(100)
    text = await Resolver._read_capped(resp)
    assert text == "a" * 100


# ---------------------------------------------------------------------------
# WHOIS deduplication — two concurrent check_one calls → one fetch_domain_age
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_whois_cache_deduplicates():
    call_count = 0

    async def mock_fetch(domain: str):
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0)  # yield so the second coroutine can reach _cached_whois
        return None, None

    perm = Permutation(domain="paypal.com", kind=PermutationType.TYPO)

    with patch("otacon.resolver.fetch_domain_age", side_effect=mock_fetch):
        async with Resolver() as r:
            with patch.object(r, "_resolve_a", new_callable=AsyncMock, return_value=["1.2.3.4"]):
                with patch.object(r, "_resolve_mx", new_callable=AsyncMock, return_value=[]):
                    with patch.object(r, "_check_ssl", new_callable=AsyncMock, return_value=False):
                        probe = AsyncMock(return_value=(None, None, None, None))
                        with patch.object(r, "_probe_http", new=probe):
                            with patch.object(
                                r, "_probe_wildcard",
                                new_callable=AsyncMock, return_value=frozenset(),
                            ):
                                await asyncio.gather(r.check_one(perm), r.check_one(perm))

    assert call_count == 1


# ---------------------------------------------------------------------------
# AAAA support — IPv6-only domains must still count as resolving
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolve_a_merges_a_and_aaaa():
    r = Resolver()

    async def fake_query(domain: str, rtype: str):
        return ["1.2.3.4"] if rtype == "A" else ["2001:db8::1"]

    with patch.object(r, "_query_ips", side_effect=fake_query):
        ips = await r._resolve_a("example.com")
    assert ips == ["1.2.3.4", "2001:db8::1"]


@pytest.mark.asyncio
async def test_resolve_a_ipv6_only():
    r = Resolver()

    async def fake_query(domain: str, rtype: str):
        return [] if rtype == "A" else ["2001:db8::1"]

    with patch.object(r, "_query_ips", side_effect=fake_query):
        ips = await r._resolve_a("example.com")
    assert ips == ["2001:db8::1"]


# ---------------------------------------------------------------------------
# NXDOMAIN-hijack canary — hijacked answers are discarded, real ones kept
# ---------------------------------------------------------------------------

def _patch_network(r: Resolver, *, resolve_ips: list[str]):
    """Patches all network calls on *r*; returns the contextmanager stack."""
    from contextlib import ExitStack

    stack = ExitStack()
    stack.enter_context(
        patch.object(r, "_resolve_a", new_callable=AsyncMock, return_value=resolve_ips)
    )
    stack.enter_context(
        patch.object(r, "_resolve_mx", new_callable=AsyncMock, return_value=[])
    )
    stack.enter_context(
        patch.object(r, "_check_ssl", new_callable=AsyncMock, return_value=False)
    )
    stack.enter_context(
        patch.object(
            r, "_probe_http", new=AsyncMock(return_value=(None, None, None, None))
        )
    )
    stack.enter_context(
        patch("otacon.resolver.fetch_domain_age", new=AsyncMock(return_value=(None, None)))
    )
    return stack


@pytest.mark.asyncio
async def test_hijacked_answer_discarded():
    perm = Permutation(domain="paypa1.com", kind=PermutationType.HOMOGLYPH)
    async with Resolver() as r:
        with _patch_network(r, resolve_ips=["198.51.100.7"]):
            # Canary resolves to the same IP — resolver hijacks NXDOMAIN.
            with patch.object(
                r, "_probe_wildcard",
                new_callable=AsyncMock, return_value=frozenset({"198.51.100.7"}),
            ):
                result = await r.check_one(perm)
        assert result.resolves is False
        assert result.ip_addresses == []
        assert result.is_registered is False


@pytest.mark.asyncio
async def test_genuine_answer_kept_despite_hijack():
    perm = Permutation(domain="paypa1.com", kind=PermutationType.HOMOGLYPH)
    async with Resolver() as r:
        with _patch_network(r, resolve_ips=["203.0.113.9"]):
            with patch.object(
                r, "_probe_wildcard",
                new_callable=AsyncMock, return_value=frozenset({"198.51.100.7"}),
            ):
                result = await r.check_one(perm)
        assert result.resolves is True
        assert result.ip_addresses == ["203.0.113.9"]


@pytest.mark.asyncio
async def test_no_hijack_keeps_answers():
    perm = Permutation(domain="paypa1.com", kind=PermutationType.HOMOGLYPH)
    async with Resolver() as r:
        with _patch_network(r, resolve_ips=["203.0.113.9"]):
            with patch.object(
                r, "_probe_wildcard", new_callable=AsyncMock, return_value=frozenset(),
            ):
                result = await r.check_one(perm)
        assert result.resolves is True
        assert r.dns_hijack_detected is False


@pytest.mark.asyncio
async def test_dns_hijack_detected_property():
    async with Resolver() as r:
        with patch.object(
            r, "_probe_wildcard",
            new_callable=AsyncMock, return_value=frozenset({"198.51.100.7"}),
        ):
            assert r.dns_hijack_detected is False  # canary not fired yet
            await r._wildcard_ips()
            assert r.dns_hijack_detected is True
