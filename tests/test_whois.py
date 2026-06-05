"""Tests for the WHOIS / domain-age module."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from otacon.whois import fetch_domain_age, format_age

# ---------------------------------------------------------------------------
# format_age — pure formatter, no I/O
# ---------------------------------------------------------------------------

def test_format_age_none_returns_dash():
    assert format_age(None) == "—"


def test_format_age_days():
    assert format_age(6) == "6d"


def test_format_age_one_day():
    assert format_age(1) == "1d"


def test_format_age_29_days():
    assert format_age(29) == "29d"


def test_format_age_30_days_rounds_to_months():
    assert format_age(30) == "1mo"


def test_format_age_90_days_is_3_months():
    assert format_age(90) == "3mo"


def test_format_age_364_days_is_months():
    assert format_age(364) == "12mo"


def test_format_age_365_days_is_1_year():
    assert format_age(365) == "1y"


def test_format_age_730_days_is_2_years():
    assert format_age(730) == "2y"


def test_format_age_zero():
    assert format_age(0) == "0d"


# ---------------------------------------------------------------------------
# fetch_domain_age — async, mocked network
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_domain_age_returns_creation_date_and_age():
    creation = datetime.now(timezone.utc) - timedelta(days=10)
    # aio_whois returns (query_output, parsed_dict)
    with patch("otacon.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.return_value = ("raw whois text", {"created": creation})
        created, age = await fetch_domain_age("example.com")

    assert created == creation
    assert age == 10


@pytest.mark.asyncio
async def test_fetch_domain_age_returns_none_on_timeout():
    with patch("otacon.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.side_effect = asyncio.TimeoutError()
        created, age = await fetch_domain_age("example.com")

    assert created is None
    assert age is None


@pytest.mark.asyncio
async def test_fetch_domain_age_returns_none_on_generic_exception():
    with patch("otacon.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.side_effect = Exception("connection refused")
        created, age = await fetch_domain_age("example.com")

    assert created is None
    assert age is None


@pytest.mark.asyncio
async def test_fetch_domain_age_returns_none_when_created_missing():
    with patch("otacon.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.return_value = ("raw whois text", {})  # no 'created' key
        created, age = await fetch_domain_age("example.com")

    assert created is None
    assert age is None


@pytest.mark.asyncio
async def test_fetch_domain_age_normalises_naive_datetime():
    """A naive datetime from WHOIS should become timezone-aware and yield a positive age."""
    # Use a fixed old date so UTC-offset arithmetic never crosses a day boundary.
    naive_creation = datetime(2020, 1, 1, 12, 0, 0)  # no tzinfo
    with patch("otacon.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.return_value = ("raw whois text", {"created": naive_creation})
        created, age = await fetch_domain_age("example.com")

    assert created is not None
    assert created.tzinfo is not None  # must be timezone-aware after normalisation
    assert age is not None and age > 365  # clearly in the past
