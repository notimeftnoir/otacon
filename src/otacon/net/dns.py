"""Asynchronous DNS resolver client with canary NXDOMAIN hijacking detection."""

from __future__ import annotations

import asyncio
import logging
import secrets
from typing import Any, Literal

import aiodns

from .content import _strip_unsafe_chars

_log = logging.getLogger("otacon.net.dns")
DEFAULT_DNS_TIMEOUT = 3.0


class DNSClient:
    """Async DNS client wrapping aiodns with granular timeouts and sanitization."""

    def __init__(self, timeout: float = DEFAULT_DNS_TIMEOUT, tries: int = 1) -> None:
        self.timeout = timeout
        self.tries = tries
        self._resolver = aiodns.DNSResolver(timeout=timeout, tries=tries)

    @property
    def raw_resolver(self) -> aiodns.DNSResolver:
        """Access underlying aiodns resolver for test patching."""
        return self._resolver

    async def _query_raw(self, domain: str, rtype: str) -> Any:
        async with asyncio.timeout(self.timeout):
            # Prefer query_dns if available, fallback to query for mocks/compat
            if hasattr(self._resolver, "query_dns"):
                try:
                    return await self._resolver.query_dns(domain, rtype)
                except AttributeError:
                    return await self._resolver.query(domain, rtype)  # type: ignore[call-overload]
            return await self._resolver.query(domain, rtype)  # type: ignore[call-overload]

    async def query_ips(self, domain: str, rtype: Literal["A", "AAAA"]) -> list[str]:
        """Resolves A or AAAA records, returning IP strings or empty list on error."""
        try:
            records = await self._query_raw(domain, rtype)
            return [r.host for r in records]
        except Exception as exc:
            _log.debug("%s lookup failed for %s: %r", rtype, domain, exc)
            return []

    async def resolve_ips(self, domain: str) -> list[str]:
        """Resolves both A and AAAA records concurrently."""
        v4, v6 = await asyncio.gather(
            self.query_ips(domain, "A"),
            self.query_ips(domain, "AAAA"),
        )
        return v4 + v6

    async def resolve_mx(self, domain: str) -> list[str]:
        """Resolves MX mail exchange hostnames with output sanitization."""
        try:
            records = await self._query_raw(domain, "MX")
            return [_strip_unsafe_chars(r.host) for r in records]
        except Exception as exc:
            _log.debug("MX lookup failed for %s: %r", domain, exc)
            return []

    async def resolve_ns(self, domain: str) -> list[str]:
        """Resolves authoritative nameservers for domain."""
        try:
            records = await self._query_raw(domain, "NS")
            return [_strip_unsafe_chars(r.host).lower() for r in records]
        except Exception as exc:
            _log.debug("NS lookup failed for %s: %r", domain, exc)
            return []

    async def resolve_txt(self, domain: str) -> list[str]:
        """Resolves TXT records."""
        try:
            records = await self._query_raw(domain, "TXT")
            results: list[str] = []
            for r in records:
                txt = r.text
                if isinstance(txt, (list, tuple)):
                    txt = "".join(
                        t.decode("utf-8", "replace") if isinstance(t, bytes) else str(t)
                        for t in txt
                    )
                elif isinstance(txt, bytes):
                    txt = txt.decode("utf-8", "replace")
                results.append(str(txt))
            return results
        except Exception as exc:
            _log.debug("TXT lookup failed for %s: %r", domain, exc)
            return []

    async def probe_wildcard(self) -> frozenset[str]:
        """Detects NXDOMAIN hijacking by resolving a nonexistent randomized domain."""
        nonce = f"otacon-wildcard-{secrets.token_hex(8)}.com"
        ips = frozenset(await self.resolve_ips(nonce))
        if ips:
            _log.debug("NXDOMAIN hijack detected: %s resolved to %s", nonce, sorted(ips))
        return ips


__all__ = [
    "DEFAULT_DNS_TIMEOUT",
    "DNSClient",
]
