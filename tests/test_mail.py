"""Tests for mail posture: SPF on lookalikes, DMARC on the user's own domain."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pycares
import pytest

from otacon import _scanner, scoring
from otacon.models import DomainResult, PermutationType
from otacon.resolver import Resolver


def _txt_zone(records: dict[str, list[bytes]]):
    """A query_dns stand-in serving TXT *records* by name; NXDOMAIN-free empty otherwise."""

    async def query(name: str, rtype: str) -> MagicMock:
        data = records.get(name, []) if rtype == "TXT" else []
        return MagicMock(
            answer=[MagicMock(type=pycares.QUERY_TYPE_TXT, data=MagicMock(data=d)) for d in data]
        )

    return query


async def _posture(records: dict[str, list[bytes]]) -> tuple[bool, str | None]:
    r = Resolver()
    with patch.object(r._dns, "query_dns", AsyncMock(side_effect=_txt_zone(records))):
        return await r.mail_posture("example.com")


@pytest.mark.asyncio
async def test_posture_reads_spf_and_dmarc_policy() -> None:
    zone = {
        "example.com": [b"google-site-verification=x", b"v=spf1 include:_spf.example -all"],
        "_dmarc.example.com": [b"v=DMARC1; p=Reject; rua=mailto:d@example.com"],
    }
    assert await _posture(zone) == (True, "reject")


@pytest.mark.asyncio
async def test_posture_without_records() -> None:
    assert await _posture({}) == (False, None)


@pytest.mark.asyncio
async def test_posture_dmarc_without_p_tag_counts_as_none() -> None:
    zone = {"_dmarc.example.com": [b"v=DMARC1; rua=mailto:d@example.com"]}
    assert await _posture(zone) == (False, "none")


@pytest.mark.asyncio
async def test_posture_ignores_sp_tag_when_reading_p() -> None:
    zone = {"_dmarc.example.com": [b"v=DMARC1; sp=reject; p=none"]}
    assert await _posture(zone) == (False, "none")


def test_spf_on_a_lookalike_scores() -> None:
    r = DomainResult(domain="exampel.com", kind=PermutationType.TYPO, resolves=True, has_spf=True)
    scored = scoring.score(r, "example.com")
    assert any("publishes SPF" in reason for reason in scored.risk_reasons)


def test_dmarc_advice_explains_both_failure_modes() -> None:
    assert "publishes no DMARC policy" in _scanner._dmarc_advice("example.com", None)
    assert "p=none" in _scanner._dmarc_advice("example.com", "none")
