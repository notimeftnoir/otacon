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

_log = logging.getLogger("otacon.whois")
_WHOIS_TIMEOUT = 10.0


async def fetch_domain_age(domain: str) -> tuple[datetime | None, int | None]:
    """Returns ``(creation_date, age_days)`` for *domain*.

    On timeout or any WHOIS error returns ``(None, None)``.
    """
    try:
        _, parsed = await asyncio.wait_for(asyncwhois.aio_whois(domain), timeout=_WHOIS_TIMEOUT)
        created = parsed.get("created")
        # asyncwhois returns a list for some TLDs (e.g. .info, .io, .pl) when the
        # WHOIS response contains multiple date fields — take the earliest entry.
        if isinstance(created, list):
            candidates = [d for d in created if isinstance(d, datetime)]
            created = min(candidates) if candidates else None
        if not isinstance(created, datetime):
            return None, None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - created).days
        if age_days < 0:
            # A creation date in the future means the value is wrong — clock skew,
            # or asyncwhois mapping an expiry field into `created` (the same class
            # of mis-parse the list handling above works around). Age is reported
            # as unknown rather than clamped to 0: `_age_points` treats 0 as the
            # freshest possible registration, so a clamp would score a 20-year-old
            # domain as a brand-new phishing one, and render "0d" — indistinguishable
            # from a genuine fresh registration. None scores nothing and renders "—".
            _log.debug("WHOIS creation date for %s is in the future: %s", domain, created)
            return created, None
        return created, age_days
    except Exception as exc:
        # Broad exception catch for WHOIS layer — network failures, parsing errors,
        # and unexpected errors are all gracefully downgraded to (None, None).
        # This ensures that WHOIS lookup failures don't crash the scan.
        _log.debug("WHOIS lookup failed for %s: %r", domain, exc)
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
