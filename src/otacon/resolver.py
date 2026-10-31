"""Compatibility shim for otacon v2.0 resolver."""

from __future__ import annotations

import asyncio

from .net.content import (
    _MAX_BODY_BYTES,
    _parse_title,
    _strip_unsafe_chars,
)
from .net.http import (
    _REDIRECT_MAX,
    HTTPProbeResult,
)
from .net.resolver import (
    DEFAULT_CONCURRENCY,
    Resolver,
)
from .net.security import (
    _PinnedHTTPTransport,
    _PinnedNetworkBackend,
)
from .net.tls import (
    _san_covers_host,
)

__all__ = [
    "DEFAULT_CONCURRENCY",
    "_MAX_BODY_BYTES",
    "_REDIRECT_MAX",
    "HTTPProbeResult",
    "Resolver",
    "_PinnedHTTPTransport",
    "_PinnedNetworkBackend",
    "_parse_title",
    "_san_covers_host",
    "_strip_unsafe_chars",
    "asyncio",
]
