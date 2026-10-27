"""Compatibility shim for otacon v2.0 resolver."""

from __future__ import annotations

import asyncio

from .core.models import DomainResult, Permutation
from .net.content import (
    _MAX_BODY_BYTES,
    _TITLE_MAX,
    _parse_title,
    _strip_unsafe_chars,
    detect_login_form,
    extract_favicon_url,
    shodan_favicon_hash,
)
from .net.http import (
    _REDIRECT_MAX,
    HTTPProbeResult,
)
from .net.resolver import (
    _DNS_TIMEOUT,
    _HTTP_DEADLINE,
    _HTTP_TIMEOUT,
    _HTTPS_GRACE,
    _HTTPS_PORT,
    DEFAULT_CONCURRENCY,
    Resolver,
)
from .net.security import (
    _PinnedHTTPTransport,
    _PinnedNetworkBackend,
    first_safe_ip,
)
from .net.tls import (
    _san_covers_host,
)
from .net.whois import (
    fetch_domain_age,
)

__all__ = [
    "DEFAULT_CONCURRENCY",
    "_DNS_TIMEOUT",
    "_HTTPS_GRACE",
    "_HTTPS_PORT",
    "_HTTP_DEADLINE",
    "_HTTP_TIMEOUT",
    "_MAX_BODY_BYTES",
    "_REDIRECT_MAX",
    "_TITLE_MAX",
    "DomainResult",
    "HTTPProbeResult",
    "Permutation",
    "Resolver",
    "_PinnedHTTPTransport",
    "_PinnedNetworkBackend",
    "_parse_title",
    "_san_covers_host",
    "_strip_unsafe_chars",
    "asyncio",
    "detect_login_form",
    "extract_favicon_url",
    "fetch_domain_age",
    "first_safe_ip",
    "shodan_favicon_hash",
]
