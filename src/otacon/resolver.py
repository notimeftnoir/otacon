"""Resolver — asynchronously checks domain variants against the network.

For each variant it collects signals indicating registration and intent:
  - A record (whether it resolves)
  - MX record (readiness for email phishing)
  - SSL certificate on :443 (active HTTPS service)
  - HTTP(S) response + Server header + redirect

Async-first architecture: hundreds of variants checked concurrently with a
limit (semaphore) so we don't flood DNS/the network. Sequentially this would
take minutes; here, seconds.
"""

from __future__ import annotations

import asyncio
import html as _html
import logging
import re
import secrets
import ssl
from datetime import datetime
from typing import Literal

import aiodns
import httpx

from . import __version__
from .models import DomainResult, Permutation
from .whois import fetch_domain_age

_log = logging.getLogger("otacon.resolver")

_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,200})", re.IGNORECASE)
_TITLE_MAX = 80


def _parse_title(body: str) -> str | None:
    """Extracts and cleans <title> text from an HTML snippet. Returns None when absent."""
    m = _TITLE_RE.search(body)
    if not m:
        return None
    title = _html.unescape(" ".join(m.group(1).split()))
    return title[:_TITLE_MAX] if title else None

# Concurrency limit — protects against DNS resolver rate-limiting and file
# descriptor exhaustion.
DEFAULT_CONCURRENCY = 50
_DNS_TIMEOUT = 3.0
_HTTP_TIMEOUT = 4.0
# Wall-clock ceiling for one HTTP probe. httpx timeouts apply per read, so a
# hostile server trickling one byte per read could otherwise hold a concurrency
# slot almost indefinitely (slow-loris against the scanner).
_HTTP_DEADLINE = 15.0
# Hard cap on how much (decompressed) HTTP body we ever read. The page <title>
# lives in <head>, so 64 KB is plenty — and the cap is what stops a hostile
# lookalike server from OOM-ing the scanner with a giant body or a gzip bomb.
_MAX_BODY_BYTES = 65536


class Resolver:
    """Concurrent domain checker. Holds shared resources (DNS, HTTP)."""

    def __init__(
        self,
        concurrency: int = DEFAULT_CONCURRENCY,
        check_http: bool = True,
    ) -> None:
        self._concurrency = concurrency
        self._sem = asyncio.Semaphore(concurrency)
        self._whois_sem = asyncio.Semaphore(4)
        self._dns = aiodns.DNSResolver(timeout=_DNS_TIMEOUT, tries=1)
        self._check_http = check_http
        # One HTTP client reused for all requests (connection pooling).
        self._http: httpx.AsyncClient | None = None
        # Per-run WHOIS cache — keyed by domain; stores an asyncio.Task so
        # concurrent check_one calls for the same domain share a single lookup.
        self._whois_cache: dict[str, asyncio.Task[tuple[datetime | None, int | None]]] = {}
        # Lazy wildcard-DNS canary (see _wildcard_ips) — created on first hit.
        self._wildcard_task: asyncio.Task[frozenset[str]] | None = None

    async def __aenter__(self) -> Resolver:
        self._http = httpx.AsyncClient(
            timeout=_HTTP_TIMEOUT,
            follow_redirects=False,   # we want to see redirects, not follow them blindly
            verify=False,             # fakes often have bad certs — we inspect them anyway
            headers={"User-Agent": f"Otacon/{__version__} (+domain-monitoring)"},
            # Bound the connection pool to the scan's concurrency so a burst
            # of slow hostile hosts can't pile up file descriptors.
            limits=httpx.Limits(
                max_connections=self._concurrency,
                max_keepalive_connections=self._concurrency,
            ),
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._http is not None:
            await self._http.aclose()

    async def _query_ips(self, domain: str, rtype: Literal["A", "AAAA"]) -> list[str]:
        try:
            records = await self._dns.query(domain, rtype)
            return [r.host for r in records]
        except Exception as exc:
            # pycares.AresError is not a subclass of aiodns.error.DNSError in all
            # versions, so we catch broadly — DNS queries are fire-and-forget.
            _log.debug("%s lookup failed for %s: %r", rtype, domain, exc)
            return []

    async def _resolve_a(self, domain: str) -> list[str]:
        """Returns IPv4 + IPv6 addresses (A and AAAA). Empty = does not resolve.

        AAAA matters: an IPv6-only lookalike resolves fine in every modern
        browser, so reporting it as unregistered would be a false negative.
        """
        v4, v6 = await asyncio.gather(
            self._query_ips(domain, "A"), self._query_ips(domain, "AAAA")
        )
        return v4 + v6

    async def _probe_wildcard(self) -> frozenset[str]:
        """Resolves a random nonexistent domain to detect NXDOMAIN hijacking.

        Some ISP/captive-portal resolvers answer every query with their own
        "search helper" IP, which would make *every* variant look registered.
        A nonce that should never exist exposes that: any IPs returned here are
        the hijacker's, and variants resolving only to them are treated as
        unregistered.
        """
        nonce = f"otacon-wildcard-{secrets.token_hex(8)}.com"
        ips = frozenset(await self._resolve_a(nonce))
        if ips:
            _log.debug("NXDOMAIN hijack detected: %s resolved to %s", nonce, sorted(ips))
        return ips

    async def _wildcard_ips(self) -> frozenset[str]:
        """Lazy, shared canary lookup — runs at most once per Resolver."""
        if self._wildcard_task is None:
            self._wildcard_task = asyncio.create_task(self._probe_wildcard())
        return await self._wildcard_task

    @property
    def dns_hijack_detected(self) -> bool:
        """True when the canary fired — the local resolver hijacks NXDOMAIN."""
        t = self._wildcard_task
        return bool(t is not None and t.done() and not t.cancelled() and t.result())

    async def _resolve_mx(self, domain: str) -> list[str]:
        """Returns MX records. Presence = the domain can send/receive mail."""
        try:
            records = await self._dns.query(domain, "MX")
            return [r.host for r in records]
        except Exception as exc:
            _log.debug("MX lookup failed for %s: %r", domain, exc)
            return []

    async def _check_ssl(self, domain: str) -> bool:
        """Checks whether there is an active TLS handshake on :443."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            fut = asyncio.open_connection(domain, 443, ssl=ctx)
            _, writer = await asyncio.wait_for(fut, timeout=_HTTP_TIMEOUT)
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError, ssl.SSLError, UnicodeError):
            return False

    @staticmethod
    async def _read_capped(resp: httpx.Response) -> str:
        """Reads at most ``_MAX_BODY_BYTES`` of the (decompressed) body.

        Streaming + early break means we never materialise more than the cap in
        memory, even when the server advertises gzip and unpacks to gigabytes —
        httpx decompresses lazily as we iterate, so breaking stops the bomb.
        """
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if total >= _MAX_BODY_BYTES:
                break
        return b"".join(chunks)[:_MAX_BODY_BYTES].decode("utf-8", "replace")

    async def _probe_http(
        self, domain: str
    ) -> tuple[int | None, str | None, str | None, str | None]:
        """Tries HTTPS and HTTP in parallel. Returns (status, server, redirect, title)."""
        if self._http is None:
            raise RuntimeError("Resolver._probe_http called outside async context manager")

        http = self._http

        async def _get(scheme: str) -> tuple[int, str | None, str | None, str | None]:
            # stream() so we can bound the body read — see _read_capped.
            async with http.stream("GET", f"{scheme}://{domain}") as resp:
                location = resp.headers.get("location")
                server = resp.headers.get("server")
                title: str | None = None
                if 200 <= resp.status_code < 300:
                    title = _parse_title(await self._read_capped(resp))
                return resp.status_code, server, location, title

        # Check both schemes in parallel; each gets a hard wall-clock deadline
        # (httpx timeouts are per read — see _HTTP_DEADLINE). HTTPS wins ties.
        outcomes = await asyncio.gather(
            asyncio.wait_for(_get("https"), _HTTP_DEADLINE),
            asyncio.wait_for(_get("http"), _HTTP_DEADLINE),
            return_exceptions=True,
        )
        for outcome in outcomes:
            if not isinstance(outcome, BaseException):
                return outcome
            if not isinstance(
                outcome, (httpx.HTTPError, UnicodeError, OSError, asyncio.TimeoutError)
            ):
                raise outcome  # unexpected bug — surface it to check_one's logger
        return None, None, None, None

    async def _fetch_whois(self, domain: str) -> tuple[datetime | None, int | None]:
        async with self._whois_sem:
            return await fetch_domain_age(domain)

    async def _cached_whois(self, domain: str) -> tuple[datetime | None, int | None]:
        """Returns WHOIS age data, deduplicated per domain per run."""
        if domain not in self._whois_cache:
            self._whois_cache[domain] = asyncio.create_task(self._fetch_whois(domain))
        return await self._whois_cache[domain]

    async def check_one(self, perm: Permutation) -> DomainResult:
        """Full check of a single variant. Bounded by the semaphore."""
        async with self._sem:
            try:
                result = DomainResult(
                    domain=perm.domain, kind=perm.kind, note=perm.note
                )

                # MX is checked independently of A — mail-only phishing domains
                # often have MX but no A record (no web presence by design).
                ips, mx = await asyncio.gather(
                    self._resolve_a(perm.domain), self._resolve_mx(perm.domain)
                )

                if ips:
                    # Discard hits that only point at an NXDOMAIN-hijacking
                    # resolver's IPs — they'd register as false positives.
                    wildcard = await self._wildcard_ips()
                    if wildcard and set(ips) <= wildcard:
                        _log.debug("ignoring hijacked answer for %s: %s", perm.domain, ips)
                        ips = []

                result.ip_addresses = ips
                result.resolves = bool(ips)
                result.mx_records = mx
                result.has_mx = bool(mx)

                # SSL and HTTP only make sense when there's an IP to connect to.
                if result.resolves and self._check_http:
                    ssl_ok, (status, server, redirect, title) = await asyncio.gather(
                        self._check_ssl(perm.domain),
                        self._probe_http(perm.domain),
                    )
                    result.has_ssl = ssl_ok
                    result.http_status = status
                    result.server_header = server
                    result.redirects_to = redirect
                    result.page_title = title

                # WHOIS only for registered domains — unregistered aren't worth the quota.
                if result.is_registered:
                    created, age = await self._cached_whois(perm.domain)
                    result.created_at = created
                    result.age_days = age

                return result
            except Exception as exc:
                # Broad catch is intentional — an unhandled exception here would
                # close the shared httpx client and crash every other concurrent
                # check_one coroutine. Graceful degradation beats a precise catch.
                _log.debug("check_one failed for %s: %r", perm.domain, exc)
                return DomainResult(domain=perm.domain, kind=perm.kind, note=perm.note)

