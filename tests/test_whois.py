"""Tests for the WHOIS / domain-age module."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
import respx

from otacon.net.whois import _fetch_rdap, fetch_domain_age, format_age


@pytest.fixture(autouse=True)
def _disable_live_rdap():
    """Ensures unit tests don't make unexpected live RDAP queries to the internet."""
    with patch("otacon.net.whois._fetch_rdap", return_value=None):
        yield


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
    creation = datetime.now(UTC) - timedelta(days=10)
    # aio_whois returns (query_output, parsed_dict)
    with patch("otacon.net.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.return_value = ("raw whois text", {"created": creation})
        created, age = await fetch_domain_age("example.com")

    assert created == creation
    assert age == 10


@pytest.mark.asyncio
async def test_fetch_domain_age_returns_none_on_timeout():
    with patch("otacon.net.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.side_effect = TimeoutError()
        created, age = await fetch_domain_age("example.com")

    assert created is None
    assert age is None


@pytest.mark.asyncio
async def test_fetch_domain_age_returns_none_on_generic_exception():
    with patch("otacon.net.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.side_effect = Exception("connection refused")
        created, age = await fetch_domain_age("example.com")

    assert created is None
    assert age is None


@pytest.mark.asyncio
async def test_fetch_domain_age_returns_none_when_created_missing():
    with patch("otacon.net.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.return_value = ("raw whois text", {})  # no 'created' key
        created, age = await fetch_domain_age("example.com")

    assert created is None
    assert age is None


@pytest.mark.asyncio
async def test_fetch_domain_age_normalises_naive_datetime():
    """A naive datetime from WHOIS should become timezone-aware and yield a positive age."""
    # Use a fixed old date so UTC-offset arithmetic never crosses a day boundary.
    naive_creation = datetime(2020, 1, 1, 12, 0, 0)  # no tzinfo
    with patch("otacon.net.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.return_value = ("raw whois text", {"created": naive_creation})
        created, age = await fetch_domain_age("example.com")

    assert created is not None
    assert created.tzinfo is not None  # must be timezone-aware after normalisation
    assert age is not None and age > 365  # clearly in the past


@pytest.mark.asyncio
async def test_fetch_domain_age_reports_future_date_as_unknown_age():
    """A future creation date (clock skew / mis-parse) yields an unknown age, not 0.

    0 would be scored as the freshest possible registration and rendered "0d" —
    indistinguishable from a genuine just-registered phishing domain. None scores
    nothing and renders "—", while the raw date is kept so the operator can see
    the WHOIS data itself was wrong.
    """
    future_creation = datetime.now(UTC) + timedelta(days=5)
    with patch("otacon.net.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.return_value = ("raw whois text", {"created": future_creation})
        created, age = await fetch_domain_age("example.com")

    assert created == future_creation  # raw date preserved for audit
    assert age is None


@pytest.mark.asyncio
async def test_future_creation_date_scores_no_age_points():
    """The unknown age from a future date must not earn the fresh-registration bonus."""
    from otacon.core.models import DomainResult
    from otacon.core.types import PermutationType
    from otacon.scoring import ScoringWeights, _age_points

    future_creation = datetime.now(UTC) + timedelta(days=5)
    with patch("otacon.net.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.return_value = ("raw whois text", {"created": future_creation})
        _created, age = await fetch_domain_age("example.com")

    result = DomainResult(domain="evil.com", kind=PermutationType.TYPO, age_days=age)
    reasons: list[str] = []
    assert _age_points(result, reasons, ScoringWeights()) == 0
    assert reasons == []


@pytest.mark.asyncio
async def test_fetch_domain_age_handles_list_of_datetimes():
    """asyncwhois returns a list for some TLDs — earliest date should be used."""
    d1 = datetime(2021, 6, 1, tzinfo=UTC)
    d2 = datetime(2019, 3, 15, tzinfo=UTC)  # earlier — should be picked
    with patch("otacon.net.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.return_value = ("raw", {"created": [d1, d2]})
        created, age = await fetch_domain_age("example.info")

    assert created == d2
    assert age is not None and age > 365


@pytest.mark.asyncio
async def test_fetch_domain_age_handles_list_with_non_datetime_entries():
    """List may contain non-datetime entries that should be filtered out."""
    d = datetime(2020, 1, 1, tzinfo=UTC)
    with patch("otacon.net.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.return_value = ("raw", {"created": ["not-a-date", None, d]})
        created, _age = await fetch_domain_age("example.info")

    assert created == d


@pytest.mark.asyncio
async def test_fetch_domain_age_handles_empty_list():
    """Empty list for 'created' should return (None, None)."""
    with patch("otacon.net.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_lookup:
        mock_lookup.return_value = ("raw", {"created": []})
        created, age = await fetch_domain_age("example.info")

    assert created is None
    assert age is None


# ---------------------------------------------------------------------------
# RDAP lookup (RFC 7480-7484)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_rdap_parses_registration_event():
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get("https://rdap.org/domain/example.com").mock(
            return_value=respx.MockResponse(
                200,
                json={
                    "events": [
                        {"eventAction": "last update", "eventDate": "2024-05-01T00:00:00Z"},
                        {"eventAction": "registration", "eventDate": "2023-01-15T10:30:00Z"},
                    ]
                },
            )
        )
        created = await _fetch_rdap("example.com")

    assert created == datetime(2023, 1, 15, 10, 30, 0, tzinfo=UTC)


@pytest.mark.asyncio
async def test_fetch_domain_age_uses_rdap_first_without_whois():
    fake_created = datetime.now(UTC) - timedelta(days=25)
    with patch("otacon.net.whois._fetch_rdap", return_value=fake_created):
        with patch("otacon.net.whois.asyncwhois.aio_whois", new_callable=AsyncMock) as mock_whois:
            created, age = await fetch_domain_age("example.com")

    assert created == fake_created
    assert age == 25
    mock_whois.assert_not_called()


@pytest.mark.asyncio
async def test_fetch_rdap_returns_none_on_http_error():
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get("https://rdap.org/domain/not-found.com").mock(
            return_value=respx.MockResponse(404)
        )
        created = await _fetch_rdap("not-found.com")

    assert created is None
