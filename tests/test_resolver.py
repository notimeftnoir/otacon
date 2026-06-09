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
                            await asyncio.gather(r.check_one(perm), r.check_one(perm))

    assert call_count == 1
