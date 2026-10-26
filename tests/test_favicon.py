"""Tests for the Shodan-compatible favicon hash and the clone signal it feeds."""

from __future__ import annotations

import base64

import pytest
import respx

from otacon import favicon, scoring
from otacon.models import DomainResult, PermutationType
from otacon.resolver import Resolver

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40


@pytest.mark.parametrize(
    ("data", "seed", "expected"),
    [
        # Values cross-checked against the reference mmh3 package.
        (b"", 0, 0),
        (b"", 1, 0x514E28B7),
        (b"foo", 0, -156908512),
        (b"hello", 0, 613153351),
    ],
)
def test_murmur3_matches_reference_vectors(data: bytes, seed: int, expected: int) -> None:
    assert favicon.murmur3_32(data, seed) == expected


def test_shodan_hash_is_murmur_of_line_wrapped_base64() -> None:
    blob = bytes(range(256)) * 3  # long enough for several 76-char lines
    assert favicon.shodan_hash(blob) == favicon.murmur3_32(base64.encodebytes(blob))


@pytest.mark.parametrize(
    ("data", "is_icon"),
    [
        (b"\x00\x00\x01\x00rest", True),
        (PNG, True),
        (b"  <svg xmlns='http://www.w3.org/2000/svg'/>", True),
        (b"<!doctype html><title>Not found</title>", False),
        (b"", False),
    ],
)
def test_looks_like_icon(data: bytes, is_icon: bool) -> None:
    assert favicon.looks_like_icon(data) is is_icon


@pytest.mark.asyncio
async def test_resolver_hashes_a_served_icon_and_falls_back_to_http() -> None:
    async with Resolver() as r:
        with respx.mock(assert_all_called=False) as router:
            router.get("https://x.example/favicon.ico").respond(404)
            router.get("http://x.example/favicon.ico").respond(200, content=PNG)
            assert await r._favicon("x.example") == favicon.shodan_hash(PNG)


@pytest.mark.asyncio
async def test_resolver_ignores_a_soft_404_page() -> None:
    async with Resolver() as r:
        with respx.mock(assert_all_called=False) as router:
            router.get("https://x.example/favicon.ico").respond(200, html="<html>nope</html>")
            assert await r._favicon("x.example") is None


def test_identical_favicon_scores_as_a_clone() -> None:
    r = DomainResult(
        domain="exampel.com", kind=PermutationType.TYPO, resolves=True, favicon_hash=1234
    )
    assert any("exact favicon" in x for x in scoring.score(r, target_favicon=1234).risk_reasons)
    r2 = r.model_copy(update={"risk_reasons": []})
    assert not any("favicon" in x for x in scoring.score(r2, target_favicon=999).risk_reasons)
