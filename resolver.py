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
import ssl
import warnings

import aiodns
import httpx

from .models import DomainResult, Permutation

# We intentionally probe with verify=False (suspicious certs are the point),
# so silence the resulting urllib3/httpx warning to keep output clean.
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Concurrency limit — protects against DNS resolver rate-limiting and file
# descriptor exhaustion.
_DEFAULT_CONCURRENCY = 50
_DNS_TIMEOUT = 3.0
_HTTP_TIMEOUT = 4.0


class Resolver:
    """Concurrent domain checker. Holds shared resources (DNS, HTTP)."""

    def __init__(
        self,
        concurrency: int = _DEFAULT_CONCURRENCY,
        check_http: bool = True,
    ) -> None:
        self._sem = asyncio.Semaphore(concurrency)
        self._dns = aiodns.DNSResolver(timeout=_DNS_TIMEOUT, tries=1)
        self._check_http = check_http
        # One HTTP client reused for all requests (connection pooling).
        self._http: httpx.AsyncClient | None = None

    async def __aenter__(self) -> Resolver:
        self._http = httpx.AsyncClient(
            timeout=_HTTP_TIMEOUT,
            follow_redirects=False,   # we want to see redirects, not follow them blindly
            verify=False,             # fakes often have bad certs — we inspect them anyway
            headers={"User-Agent": "Otacon/1.0 (+domain-monitoring)"},
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._http is not None:
            await self._http.aclose()

    async def _resolve_a(self, domain: str) -> list[str]:
        """Returns the list of IP addresses (A record). Empty = does not resolve."""
        try:
            records = await self._dns.query(domain, "A")
            return [r.host for r in records]
        except (aiodns.error.DNSError, UnicodeError):
            return []

    async def _resolve_mx(self, domain: str) -> list[str]:
        """Returns MX records. Presence = the domain can send/receive mail."""
        try:
            records = await self._dns.query(domain, "MX")
            return [r.host for r in records]
        except (aiodns.error.DNSError, UnicodeError):
            return []

    async def _check_ssl(self, domain: str) -> bool:
        """Checks whether there is an active TLS handshake on :443."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            fut = asyncio.open_connection(domain, 443, ssl=ctx)
            _, writer = await asyncio.wait_for(fut, timeout=_DNS_TIMEOUT)
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError, ssl.SSLError, UnicodeError):
            return False

    async def _probe_http(self, domain: str) -> tuple[int | None, str | None, str | None]:
        """Tries HTTPS, then HTTP. Returns (status, server, redirect_target)."""
        assert self._http is not None
        for scheme in ("https", "http"):
            try:
                resp = await self._http.get(f"{scheme}://{domain}")
                location = resp.headers.get("location")
                return resp.status_code, resp.headers.get("server"), location
            except (httpx.HTTPError, UnicodeError, OSError):
                continue
        return None, None, None

    async def check_one(self, perm: Permutation) -> DomainResult:
        """Full check of a single variant. Bounded by the semaphore."""
        async with self._sem:
            result = DomainResult(
                domain=perm.domain, kind=perm.kind, note=perm.note
            )

            ips = await self._resolve_a(perm.domain)
            result.ip_addresses = ips
            result.resolves = bool(ips)

            # MX and HTTP only make sense if the domain exists at all.
            if result.resolves:
                mx = await self._resolve_mx(perm.domain)
                result.mx_records = mx
                result.has_mx = bool(mx)

                if self._check_http:
                    ssl_ok, (status, server, redirect) = await asyncio.gather(
                        self._check_ssl(perm.domain),
                        self._probe_http(perm.domain),
                    )
                    result.has_ssl = ssl_ok
                    result.http_status = status
                    result.server_header = server
                    result.redirects_to = redirect

            return result

    async def check_all(self, perms: list[Permutation]) -> list[DomainResult]:
        """Checks all variants concurrently.

        return_exceptions=True ensures a single unexpected failure does not abort
        the whole scan; failed checks are dropped rather than raised.
        """
        tasks = [self.check_one(p) for p in perms]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, DomainResult)]
