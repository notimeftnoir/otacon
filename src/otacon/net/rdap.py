"""RDAP (Registration Data Access Protocol) client over HTTPS (RFC 7480-7484)."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

import httpx

_log = logging.getLogger("otacon.net.rdap")
DEFAULT_RDAP_TIMEOUT = 5.0


async def fetch_rdap(
    domain: str, client: httpx.AsyncClient | None = None, timeout: float = DEFAULT_RDAP_TIMEOUT
) -> datetime | None:
    """Queries RDAP over HTTPS for domain registration date."""
    url = f"https://rdap.org/domain/{domain}"
    headers = {"Accept": "application/rdap+json, application/json", "User-Agent": "otacon/2.0"}
    try:
        if client is not None:
            async with asyncio.timeout(timeout):
                resp = await client.get(url, headers=headers)
        else:
            async with httpx.AsyncClient(follow_redirects=True) as c:
                async with asyncio.timeout(timeout):
                    resp = await c.get(url, headers=headers)
        if resp.status_code != 200:
            return None
        data: Any = resp.json()
        events = data.get("events")
        if not isinstance(events, list):
            return None
        candidates: list[datetime] = []
        for ev in events:
            if isinstance(ev, dict) and ev.get("eventAction") in ("registration", "created"):
                raw_date = ev.get("eventDate")
                if isinstance(raw_date, str):
                    try:
                        clean_str = raw_date.replace("Z", "+00:00")
                        dt = datetime.fromisoformat(clean_str)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=UTC)
                        candidates.append(dt)
                    except ValueError:
                        pass
        return min(candidates) if candidates else None
    except Exception as exc:
        _log.debug("RDAP lookup failed for %s: %r", domain, exc)
        return None


__all__ = ["DEFAULT_RDAP_TIMEOUT", "fetch_rdap"]
