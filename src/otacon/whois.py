"""WHOIS / domain-age lookup.

Fetches domain registration data asynchronously and computes domain age as
a scoring signal. A freshly registered lookalike is the strongest predictor
of an active phishing campaign.

Graceful degradation: any failure (timeout, parse error, unreachable server)
returns (None, None) so the rest of the scan continues unaffected.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import asyncwhois
import httpx

_log = logging.getLogger("otacon.whois")
_RDAP_TIMEOUT = 5.0
_WHOIS_TIMEOUT = 10.0


async def _fetch_rdap(domain: str, client: httpx.AsyncClient | None = None) -> datetime | None:
    """Attempts to fetch registration date using RDAP over HTTPS (RFC 7480-7484)."""
    url = f"https://rdap.org/domain/{domain}"
    headers = {"Accept": "application/rdap+json, application/json", "User-Agent": "otacon/1.0"}
    try:
        if client is not None:
            resp = await client.get(url, headers=headers, timeout=_RDAP_TIMEOUT)
        else:
            async with httpx.AsyncClient(follow_redirects=True) as c:
                resp = await c.get(url, headers=headers, timeout=_RDAP_TIMEOUT)
        if resp.status_code != 200:
            return None
        data = resp.json()
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
                            dt = dt.replace(tzinfo=timezone.utc)
                        candidates.append(dt)
                    except ValueError:
                        pass
        return min(candidates) if candidates else None
    except Exception as exc:
        _log.debug("RDAP lookup failed for %s: %r", domain, exc)
        return None


async def fetch_domain_age(
    domain: str, client: httpx.AsyncClient | None = None
) -> tuple[datetime | None, int | None]:
    """Returns ``(creation_date, age_days)`` for *domain*.

    Queries RDAP over HTTPS first (RFC 7480-7484) for faster, firewall-friendly
    JSON registration data; falls back to traditional TCP port 43 WHOIS on failure.
    On timeout or error in both, gracefully returns ``(None, None)``.
    """
    created: datetime | None = None
    try:
        created = await _fetch_rdap(domain, client=client)
    except Exception as exc:
        _log.debug("RDAP query exception for %s: %r", domain, exc)

    if created is None:
        try:
            _, parsed = await asyncio.wait_for(asyncwhois.aio_whois(domain), timeout=_WHOIS_TIMEOUT)
            raw_created = parsed.get("created")
            # asyncwhois returns a list for some TLDs (e.g. .info, .io, .pl) when the
            # WHOIS response contains multiple date fields — take the earliest entry.
            if isinstance(raw_created, list):
                candidates = [d for d in raw_created if isinstance(d, datetime)]
                created = min(candidates) if candidates else None
            elif isinstance(raw_created, datetime):
                created = raw_created
        except Exception as exc:
            # Broad exception catch for WHOIS layer — network failures, parsing errors,
            # and unexpected errors are all gracefully downgraded to (None, None).
            # This ensures that WHOIS lookup failures don't crash the scan.
            _log.debug("WHOIS lookup failed for %s: %r", domain, exc)
            return None, None

    if not isinstance(created, datetime):
        return None, None

    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - created).days
    if age_days < 0:
        # A creation date in the future means the value is wrong — clock skew,
        # or asyncwhois mapping an expiry field into `created`.
        _log.debug("Registration creation date for %s is in the future: %s", domain, created)
        return created, None
    return created, age_days


def format_age(age_days: int | None) -> str:
    """Compact human-readable age: ``6d``, ``3mo``, ``2y``, or ``—``."""
    if age_days is None:
        return "—"
    if age_days < 30:
        return f"{age_days}d"
    if age_days < 365:
        return f"{age_days // 30}mo"
    return f"{age_days // 365}y"
