"""Asynchronous DNS resolver client with canary NXDOMAIN hijacking detection."""

from __future__ import annotations

import asyncio
import logging
import secrets
from typing import Any, Literal

import aiodns

from .content import _strip_unsafe_chars

_log = logging.getLogger("otacon.net.dns")
# aiodns >= 4 renamed query() -> query_dns() and changed the return type from a
# flat list of records with .host/.text to a DNSResult whose .answer holds
# DNSRecords with typed .data payloads (addr / exchange / nsdname / data).
# Iterating a DNSResult raises TypeError, which the callers' graceful-degradation
# handlers swallow — every domain then looks unregistered. Normalise both shapes
# here so the call sites keep reading .host and .text.
_HOST_FIELDS = ("addr", "exchange", "nsdname", "cname", "dname", "target")


class _Record:
    """Adapts an aiodns>=4 DNSRecord to the pre-4.0 .host / .text / .priority shape."""

    __slots__ = ("_data", "ttl")

    def __init__(self, record: Any) -> None:
        self._data = record.data
        self.ttl = getattr(record, "ttl", 0)

    @property
    def host(self) -> str:
        """The single hostname or address this record points at."""
        for field in _HOST_FIELDS:
            value = getattr(self._data, field, None)
            if value is not None:
                return str(value)
        return ""

    @property
    def text(self) -> str:
        """TXT payload decoded to str."""
        payload = getattr(self._data, "data", "")
        if isinstance(payload, bytes):
            return payload.decode("utf-8", "replace")
        return str(payload)

    @property
    def priority(self) -> int:
        """MX / SRV priority, 0 when the record type has none."""
        return int(getattr(self._data, "priority", 0))


async def query_records(resolver: Any, name: str, rtype: str) -> list[Any]:
    """Queries *rtype* records for *name*, normalised across aiodns versions.

    Returns records exposing ``.host`` / ``.text`` whether the resolver is an
    aiodns>=4 instance (DNSResult), a pre-4.0 one (plain list), or a test double
    patched onto ``.query``.
    """
    from unittest.mock import Mock

    query_fn = getattr(resolver, "query", None)
    is_custom = isinstance(query_fn, Mock) or (
        hasattr(resolver, "__dict__") and "query" in resolver.__dict__
    )
    if is_custom or not hasattr(resolver, "query_dns"):
        result = await resolver.query(name, rtype)
    else:
        result = await resolver.query_dns(name, rtype)
    answer = getattr(result, "answer", None)
    if answer is None:
        return list(result)
    return [_Record(r) for r in answer]


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

    async def _query_raw(self, domain: str, rtype: str) -> list[Any]:
        async with asyncio.timeout(self.timeout):
            return await query_records(self._resolver, domain, rtype)

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
    "query_records",
]
