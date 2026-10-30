"""HTTP and HTTPS racing probe client with capped streaming to prevent decompression bombs."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any
from urllib.parse import urlparse

import httpx

from .content import (
    _MAX_BODY_BYTES,
    _parse_title,
    _strip_unsafe_chars,
    detect_login_form,
    extract_favicon_url,
    shodan_favicon_hash,
)

_REDIRECT_MAX = 200
# Major only: a scan should not need a release to keep its UA honest, and
# three separate literals had drifted from the release they shipped in.
USER_AGENT = "Otacon/4 (+domain-monitoring)"
DEFAULT_HTTP_TIMEOUT = 4.0
HTTP_DEADLINE = 15.0
HTTPS_GRACE = 2.0


class HTTPProbeResult(tuple[Any, ...]):
    """Probe result tuple (status, server, redirect, title) with extra fingerprint attributes."""

    status: int | None
    server: str | None
    redirect: str | None
    title: str | None
    has_login_form: bool
    favicon_hash: int | None

    def __new__(
        cls,
        status: int | None,
        server: str | None,
        redirect: str | None,
        title: str | None,
        has_login_form: bool = False,
        favicon_hash: int | None = None,
    ) -> HTTPProbeResult:
        obj = super().__new__(cls, (status, server, redirect, title))
        obj.status = status
        obj.server = server
        obj.redirect = redirect
        obj.title = title
        obj.has_login_form = has_login_form
        obj.favicon_hash = favicon_hash
        return obj


async def read_capped_body(resp: httpx.Response) -> str:
    """Streams and bounds response body to _MAX_BODY_BYTES preventing decompression bombs."""
    chunks: list[bytes] = []
    total = 0
    async for chunk in resp.aiter_bytes():
        chunks.append(chunk)
        total += len(chunk)
        if total >= _MAX_BODY_BYTES:
            break
    return b"".join(chunks)[:_MAX_BODY_BYTES].decode("utf-8", "replace")


async def probe_http(
    domain: str,
    http_client: httpx.AsyncClient,
    deadline: float = HTTP_DEADLINE,
    grace: float = HTTPS_GRACE,
) -> HTTPProbeResult:
    """Probes HTTP and HTTPS in parallel with racing grace period and body capping."""

    async def _fetch_favicon(scheme: str, fav_url: str) -> int | None:
        with contextlib.suppress(Exception):
            parsed = urlparse(fav_url)
            host = parsed.hostname.lower().rstrip(".") if parsed.hostname else ""
            if host and host != domain.lower().rstrip("."):
                fav_url = f"{scheme}://{domain}/favicon.ico"
            fav_resp = await http_client.get(fav_url, timeout=2.5)
            if 200 <= fav_resp.status_code < 300 and fav_resp.content:
                return shodan_favicon_hash(fav_resp.content[:_MAX_BODY_BYTES])
        return None

    async def _get(scheme: str) -> HTTPProbeResult:
        async with http_client.stream("GET", f"{scheme}://{domain}") as resp:
            location = resp.headers.get("location")
            if location is not None:
                location = _strip_unsafe_chars(location)[:_REDIRECT_MAX]
            server = resp.headers.get("server")
            if server is not None:
                server = _strip_unsafe_chars(server)
            title: str | None = None
            has_login = False
            fav_hash: int | None = None
            if 200 <= resp.status_code < 300:
                body = await read_capped_body(resp)
                title = _parse_title(body)
                has_login = detect_login_form(body)
                fav_url = extract_favicon_url(f"{scheme}://{domain}", body)
                fav_hash = await _fetch_favicon(scheme, fav_url)
            return HTTPProbeResult(resp.status_code, server, location, title, has_login, fav_hash)

    async def _timed_get(scheme: str) -> HTTPProbeResult:
        async with asyncio.timeout(deadline):
            return await _get(scheme)

    https_task = asyncio.create_task(_timed_get("https"))
    http_task = asyncio.create_task(_timed_get("http"))

    done, pending = await asyncio.wait([https_task, http_task], return_when=asyncio.FIRST_COMPLETED)
    if https_task in done:
        https_exc = https_task.exception()
        if https_exc is None:
            http_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await http_task
            return https_task.result()
        if not isinstance(https_exc, (httpx.HTTPError, UnicodeError, OSError, TimeoutError)):
            http_task.cancel()
            raise https_exc
        if http_task in pending:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await http_task
        http_exc = http_task.exception()
        if http_exc is None:
            return http_task.result()
        if not isinstance(http_exc, (httpx.HTTPError, UnicodeError, OSError, TimeoutError)):
            raise http_exc
        return HTTPProbeResult(None, None, None, None, False, None)
    else:
        http_exc = http_task.exception()
        if http_exc is None:
            try:
                async with asyncio.timeout(grace):
                    return await https_task
            except (TimeoutError, httpx.HTTPError, UnicodeError, OSError):
                return http_task.result()
        if not isinstance(http_exc, (httpx.HTTPError, UnicodeError, OSError, TimeoutError)):
            https_task.cancel()
            raise http_exc
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await https_task
        https_exc = https_task.exception()
        if https_exc is None:
            return https_task.result()
        if not isinstance(https_exc, (httpx.HTTPError, UnicodeError, OSError, TimeoutError)):
            raise https_exc
        return HTTPProbeResult(None, None, None, None, False, None)


__all__ = [
    "DEFAULT_HTTP_TIMEOUT",
    "HTTPS_GRACE",
    "HTTP_DEADLINE",
    "USER_AGENT",
    "_REDIRECT_MAX",
    "HTTPProbeResult",
    "probe_http",
    "read_capped_body",
]
