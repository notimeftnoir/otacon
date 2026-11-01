"""Asynchronous DNS resolver client with canary NXDOMAIN hijacking detection."""

from __future__ import annotations

import logging
from typing import Any

import aiodns

_log = logging.getLogger("otacon.net.dns")
# aiodns >= 4 renamed query() -> query_dns() and changed the return type from a
# flat list of records with .host/.text to a DNSResult whose .answer holds
# DNSRecords with typed .data payloads (addr / exchange / nsdname / data).
# Iterating a DNSResult raises TypeError, which the callers' graceful-degradation
# handlers swallow — every domain then looks unregistered. Normalise both shapes
# here so the call sites keep reading .host and .text.
_HOST_FIELDS = ("addr", "exchange", "nsdname", "cname", "dname", "target")

# c-ares status codes that are an *answer*, not a malfunction: the name does not
# exist (ENOTFOUND) or holds no record of that type (ENODATA). Most variants in a
# scan are unregistered, so these dominate a perfectly healthy run and must not
# count as failures — otherwise the health signal is noise.
_NEGATIVE_ANSWER_CODES = frozenset({1, 4})  # ARES_ENODATA, ARES_ENOTFOUND
_ARES_ETIMEOUT = 12

NULL_MX = "."
"""RFC 7505: an MX of "." declares that the domain handles no mail at all.

c-ares reports the root exchange as an empty string, so it arrives looking like
a parse failure rather than the explicit statement it is. It is evidence that
somebody registered the name — a record had to be published — but the opposite
of evidence that the name can send or receive mail.
"""


def is_negative_answer(exc: BaseException) -> bool:
    """True when the resolver said 'no such name' / 'no data' rather than failing.

    Anything else — a timeout, SERVFAIL, a refused connection, or a TypeError
    because the library changed its return shape — is infrastructure trouble and
    means the scan cannot tell "not registered" from "could not check".
    """
    return (
        isinstance(exc, aiodns.error.DNSError)
        and bool(exc.args)
        and exc.args[0] in _NEGATIVE_ANSWER_CODES
    )


def is_timeout(exc: BaseException) -> bool:
    """True when no answer arrived at all — c-ares gave up, or the outer deadline hit."""
    if isinstance(exc, TimeoutError):
        return True
    return (
        isinstance(exc, aiodns.error.DNSError) and bool(exc.args) and exc.args[0] == _ARES_ETIMEOUT
    )


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
    aiodns>=4 instance (``query_dns``, returning a DNSResult) or a pre-4.0 one
    (``query``, returning a plain list).
    """
    query_fn = getattr(resolver, "query_dns", None) or resolver.query
    result = await query_fn(name, rtype)
    answer = getattr(result, "answer", None)
    if answer is None:
        return list(result)
    return [_Record(r) for r in answer]


__all__ = [
    "NULL_MX",
    "is_negative_answer",
    "is_timeout",
    "query_records",
]
