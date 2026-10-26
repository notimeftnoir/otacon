"""Threat intelligence: is a lookalike already reported as phishing?

Two keyless public feeds are downloaded whole and matched locally, so the
lookalike names a scan generates never leave the machine:

  - OpenPhish community feed (URLs, refreshed every few hours)
  - Phishing Army blocklist (domains, aggregated from several sources)

Feeds are cached on disk for _TTL and the stale copy is reused when a refresh
fails, so an offline scan still gets yesterday's intel. URLhaus is queried per
domain, which does send the name to abuse.ch, so it only runs when the user
opts in by setting ABUSECH_AUTH_KEY (free key from https://auth.abuse.ch/).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
import time
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

import httpx

_log = logging.getLogger("otacon.intel")

_FEEDS: dict[str, str] = {
    "OpenPhish": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    "Phishing Army": "https://phishing.army/download/phishing_army_blocklist.txt",
}
_TTL = 6 * 3600
# Phishing Army is ~3 MB; anything far bigger is not the feed we expect.
_MAX_FEED_BYTES = 32 * 1024 * 1024
_URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"
_HOST_RE = re.compile(r"[a-z0-9_-]+(\.[a-z0-9_-]+)+")
URLHAUS_KEY_ENV = "ABUSECH_AUTH_KEY"


def cache_dir() -> Path:
    """Per-user cache directory: %LOCALAPPDATA% on Windows, XDG elsewhere."""
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        base = Path(os.environ["LOCALAPPDATA"])
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "otacon"


def _host(line: str) -> str | None:
    """Hostname from a feed line (bare domain or URL), lowercased, www. dropped."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        host = urlsplit(line).hostname if "://" in line else line.split("/")[0]
    except ValueError:  # malformed URL (e.g. bad IPv6 brackets) in a public feed
        return None
    if not host:
        return None
    host = host.lower().removeprefix("www.").rstrip(".")
    # Feed lines are attacker-influenced and get printed: keep DNS-safe ACE only.
    return host if _HOST_RE.fullmatch(host) else None


def _parse(text: str) -> frozenset[str]:
    return frozenset(h for h in map(_host, text.splitlines()) if h)


async def _fetch(client: httpx.AsyncClient, url: str) -> str:
    async with client.stream("GET", url, follow_redirects=True) as resp:
        resp.raise_for_status()
        body = bytearray()
        async for chunk in resp.aiter_bytes():
            body += chunk
            if len(body) > _MAX_FEED_BYTES:
                raise ValueError(f"feed larger than {_MAX_FEED_BYTES} bytes")
    return body.decode("utf-8", "replace")


async def _load_one(client: httpx.AsyncClient, name: str, url: str, root: Path) -> frozenset[str]:
    path = root / f"{name.lower().replace(' ', '-')}.txt"
    fresh = path.exists() and time.time() - path.stat().st_mtime < _TTL
    if not fresh:
        try:
            text = await _fetch(client, url)
            root.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        except (httpx.HTTPError, OSError, ValueError) as exc:
            _log.debug("feed %s refresh failed: %r (using cache: %s)", name, exc, path.exists())
    try:
        return _parse(path.read_text(encoding="utf-8"))
    except OSError:
        return frozenset()


async def load_feeds(
    client: httpx.AsyncClient, root: Path | None = None
) -> dict[str, frozenset[str]]:
    """{feed name: hostnames}, refreshed when older than _TTL; empty on failure."""
    root = root or cache_dir()
    names = list(_FEEDS)
    sets = await asyncio.gather(*(_load_one(client, n, _FEEDS[n], root) for n in names))
    return dict(zip(names, sets, strict=True))


def match(domains: Iterable[str], feeds: dict[str, frozenset[str]]) -> dict[str, list[str]]:
    """{domain: [feed names]} for every domain a feed lists, itself or a subdomain.

    Walks each feed host's parent names against the (small) domain set rather
    than testing each domain against every host, so a 150k-host feed costs one
    pass per scan.
    """
    wanted = {d.lower() for d in domains}
    hits: dict[str, list[str]] = {}
    for name, hosts in feeds.items():
        for host in hosts:
            labels = host.split(".")
            for i in range(len(labels) - 1):
                parent = ".".join(labels[i:])
                if parent in wanted:
                    sources = hits.setdefault(parent, [])
                    if name not in sources:
                        sources.append(name)
                    break
    return hits


# Brands shorter than this only match whole tokens or label prefixes: a bare
# substring test would find "ing" in every "login".
_SUBSTRING_MIN = 5


def _mentions_brand(host: str, brand: str) -> bool:
    for label in host.split("."):
        if label.startswith(brand) or brand in label.split("-"):
            return True
        if len(brand) >= _SUBSTRING_MIN and brand in label:
            return True
    return False


def mentions(brand: str, feeds: dict[str, frozenset[str]], own_domain: str) -> dict[str, list[str]]:
    """{host: [feed names]} for listed hosts that carry *brand* in their name.

    Real phishing mostly hangs the brand off a throwaway domain
    (``allegro.id-23843.click``) that no permutation would ever produce; the
    feeds already know those hosts. *own_domain* and its subdomains are skipped.
    """
    brand = brand.lower()
    found: dict[str, list[str]] = {}
    for name, hosts in feeds.items():
        for host in hosts:
            if host == own_domain or host.endswith("." + own_domain):
                continue
            if _mentions_brand(host, brand):
                found.setdefault(host, []).append(name)
    return found


async def urlhaus_listed(client: httpx.AsyncClient, domain: str, key: str) -> bool:
    """True when URLhaus has the host on record; False on any error or no key."""
    try:
        resp = await client.post(_URLHAUS_API, data={"host": domain}, headers={"Auth-Key": key})
        data = resp.json()
        return isinstance(data, dict) and data.get("query_status") == "ok"
    except (httpx.HTTPError, ValueError) as exc:
        _log.debug("URLhaus lookup for %s failed: %r", domain, exc)
        return False
