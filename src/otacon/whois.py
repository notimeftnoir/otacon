"""WHOIS / domain-age lookup.

Fetches domain registration data asynchronously and computes domain age as
a scoring signal. A freshly registered lookalike is the strongest predictor
of an active phishing campaign.

Graceful degradation: any failure (timeout, parse error, unreachable server)
returns (None, None) so the rest of the scan continues unaffected.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import asyncwhois

_WHOIS_TIMEOUT = 5.0


async def fetch_domain_age(domain: str) -> tuple[datetime | None, int | None]:
    """Returns ``(creation_date, age_days)`` for *domain*.

    On timeout or any WHOIS error returns ``(None, None)``.
    """
    try:
        _, parsed = await asyncio.wait_for(
            asyncwhois.aio_whois(domain), timeout=_WHOIS_TIMEOUT
        )
        created = parsed.get("created")
        if not isinstance(created, datetime):
            return None, None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - created).days
        return created, age_days
    except Exception:
        return None, None


def format_age(age_days: int | None) -> str:
    """Compact human-readable age: ``6d``, ``3mo``, ``2y``, or ``—``."""
    if age_days is None:
        return "—"
    if age_days < 30:
        return f"{age_days}d"
    if age_days < 365:
        return f"{age_days // 30}mo"
    return f"{age_days // 365}y"
