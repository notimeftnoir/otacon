"""Passive DNSBL (Spamhaus DBL & SURBL) reputation lookups."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from .dns import query_records as _query_dns

_log = logging.getLogger("otacon.net.dnsbl")

_SPAMHAUS_CATEGORIES: dict[str, str] = {
    "127.0.1.2": "Spamhaus DBL (spam)",
    "127.0.1.4": "Spamhaus DBL (phishing)",
    "127.0.1.5": "Spamhaus DBL (malware)",
    "127.0.1.6": "Spamhaus DBL (botnet C2)",
    "127.0.1.102": "Spamhaus DBL (abused spam)",
    "127.0.1.104": "Spamhaus DBL (abused phishing)",
    "127.0.1.105": "Spamhaus DBL (abused malware)",
    "127.0.1.106": "Spamhaus DBL (abused botnet C2)",
}


async def check_dnsbl(
    domain: str, dns_resolver: Any, timeout: float = 3.0
) -> tuple[bool, str | None]:
    """Queries Spamhaus DBL and SURBL to check if domain is listed on threat lists."""
    dbl_query = f"{domain}.dbl.spamhaus.org"
    try:
        async with asyncio.timeout(timeout):
            records = await _query_dns(dns_resolver, dbl_query, "A")
        for r in records:
            ip = getattr(r, "host", str(r))
            if ip.startswith("127.0.1."):
                return True, _SPAMHAUS_CATEGORIES.get(ip, "Spamhaus DBL (listed)")
    except Exception as exc:
        _log.debug("DBL lookup failed for %s: %r", domain, exc)

    surbl_query = f"{domain}.multi.surbl.org"
    try:
        async with asyncio.timeout(timeout):
            records = await _query_dns(dns_resolver, surbl_query, "A")
        for r in records:
            ip = getattr(r, "host", str(r))
            if ip.startswith("127.0.0.") and ip not in ("127.0.0.1", "127.0.0.254", "127.0.0.255"):
                return True, "SURBL (listed)"
    except Exception as exc:
        _log.debug("SURBL lookup failed for %s: %r", domain, exc)

    return False, None


__all__ = ["check_dnsbl"]
