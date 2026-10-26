"""Certificate Transparency: freshly issued certificates that name the brand.

A phishing site needs HTTPS, and every publicly trusted certificate is logged
in CT within minutes of issue, often before the site is even up. crt.sh
searches those logs by keyword for free, which also finds lookalikes no
permutation produces (``allegro-pay-secure.com``).

crt.sh is slow and often down, so the lookup retries, caches each brand's
answer for _TTL, falls back to a stale copy, and says "unavailable" (None)
rather than reporting an empty result as if nothing was issued. Only
certificates from the last WINDOW_DAYS count: older ones for a common word
like "allegro" are mostly unrelated businesses, new ones are what to look at.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx

from . import intel

_log = logging.getLogger("otacon.ct")

_CRTSH = "https://crt.sh/"
_TTL = 6 * 3600
_RETRIES = 2
_BACKOFF = 2.0
WINDOW_DAYS = 30


def _issued(row: dict[str, Any]) -> datetime | None:
    try:
        return datetime.fromisoformat(str(row["not_before"])).replace(tzinfo=UTC)
    except (KeyError, ValueError):
        return None


def _names(rows: Any, brand: str, own_domain: str, since: datetime) -> dict[str, datetime]:
    """{host: earliest notBefore} for brand-bearing names issued since *since*."""
    found: dict[str, datetime] = {}
    for row in rows if isinstance(rows, list) else []:
        issued = _issued(row) if isinstance(row, dict) else None
        if issued is None or issued < since:
            continue
        for raw in str(row.get("name_value", "")).split("\n"):
            host = intel._host(raw.strip().removeprefix("*."))
            if not host or host == own_domain or host.endswith("." + own_domain):
                continue
            if intel._mentions_brand(host, brand) and (host not in found or issued < found[host]):
                found[host] = issued
    return found


async def _download(client: httpx.AsyncClient, brand: str) -> Any:
    query = {"q": brand, "output": "json", "exclude": "expired", "deduplicate": "Y"}
    url = f"{_CRTSH}?{urlencode(query)}"
    for attempt in range(_RETRIES + 1):
        try:
            return json.loads(await intel._fetch(client, url))
        except (httpx.HTTPError, ValueError) as exc:
            _log.debug("crt.sh attempt %d for %r failed: %r", attempt + 1, brand, exc)
            if attempt < _RETRIES:
                await asyncio.sleep(_BACKOFF * 2**attempt)
    return None


async def recent_certificates(
    client: httpx.AsyncClient,
    brand: str,
    own_domain: str,
    days: int = WINDOW_DAYS,
    root: Path | None = None,
) -> dict[str, datetime] | None:
    """{host: first issued} for certificates naming *brand* in the last *days*.

    None means crt.sh could not be reached and no cached answer exists.
    """
    path = (root or intel.cache_dir()) / f"ct-{re.sub(r'[^a-z0-9-]', '_', brand)}.json"
    rows: Any = None
    if path.exists() and time.time() - path.stat().st_mtime < _TTL:
        rows = _read(path)
    if rows is None:
        rows = await _download(client, brand)
        if rows is not None:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(rows), encoding="utf-8")
            except OSError as exc:
                _log.debug("could not cache CT answer: %r", exc)
        elif path.exists():
            rows = _read(path)  # stale beats nothing when crt.sh is down
    if rows is None:
        return None
    return _names(rows, brand.lower(), own_domain, datetime.now(UTC) - timedelta(days=days))


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
