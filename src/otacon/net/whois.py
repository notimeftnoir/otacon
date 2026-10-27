"""Asynchronous WHOIS and domain age retrieval with RDAP fast-path."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

import asyncwhois
import httpx

from .rdap import DEFAULT_RDAP_TIMEOUT, fetch_rdap

_log = logging.getLogger("otacon.net.whois")
DEFAULT_WHOIS_TIMEOUT = 10.0

# Backward compatibility alias
_fetch_rdap = fetch_rdap


async def fetch_domain_age(
    domain: str,
    client: httpx.AsyncClient | None = None,
    rdap_timeout: float = DEFAULT_RDAP_TIMEOUT,
    whois_timeout: float = DEFAULT_WHOIS_TIMEOUT,
) -> tuple[datetime | None, int | None]:
    """Retrieves domain creation date via RDAP first, falling back to port 43 WHOIS."""
    created: datetime | None = None
    try:
        created = await _fetch_rdap(domain, client=client, timeout=rdap_timeout)
    except Exception as exc:
        _log.debug("RDAP query exception for %s: %r", domain, exc)

    if created is None:
        try:
            async with asyncio.timeout(whois_timeout):
                _, parsed = await asyncwhois.aio_whois(domain)
            raw_created: Any = parsed.get("created")
            if isinstance(raw_created, list):
                candidates = [d for d in raw_created if isinstance(d, datetime)]
                created = min(candidates) if candidates else None
            elif isinstance(raw_created, datetime):
                created = raw_created
        except Exception as exc:
            _log.debug("WHOIS lookup failed for %s: %r", domain, exc)
            return None, None

    if not isinstance(created, datetime):
        return None, None

    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    age_days = (datetime.now(UTC) - created).days
    if age_days < 0:
        _log.debug("Registration creation date for %s is in the future: %s", domain, created)
        return created, None
    return created, age_days


def format_age(age_days: int | None) -> str:
    """Compact human-readable age representation."""
    if age_days is None:
        return "—"
    if age_days < 30:
        return f"{age_days}d"
    if age_days < 365:
        return f"{age_days // 30}mo"
    return f"{age_days // 365}y"


__all__ = [
    "DEFAULT_WHOIS_TIMEOUT",
    "_fetch_rdap",
    "fetch_domain_age",
    "format_age",
]
