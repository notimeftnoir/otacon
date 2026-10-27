"""SSRF prevention and socket IP pinning backends.

Enforces connection pinning to prevent DNS rebinding attacks and block connections
to RFC 1918, loopback, link-local, and cloud metadata IP addresses.
"""

from __future__ import annotations

from typing import Any

import httpcore
import httpx

from ..core.exceptions import SSRFBlockedError
from ..utils.validate import first_safe_ip


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Delegating backend that pins each connect to a pre-vetted, safe IP address."""

    def __init__(self, pins: dict[str, str]) -> None:
        self._pins = pins
        self._delegate = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        """Connects directly to the vetted IP pinned for host, refusing unpinned hosts."""
        ip = self._pins.get(host)
        if ip is None:
            raise httpcore.ConnectError(f"refusing unpinned connect to {host!r}")
        return await self._delegate.connect_tcp(
            ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )

    async def sleep(self, seconds: float) -> None:
        """Asynchronously pause execution."""
        await self._delegate.sleep(seconds)


class _PinnedHTTPTransport(httpx.AsyncHTTPTransport):
    """Async HTTP transport routing connections through pre-vetted IP pins."""

    def __init__(self, pins: dict[str, str], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._pool._network_backend = _PinnedNetworkBackend(pins)


def verify_safe_ips(ips: list[str]) -> str:
    """Verifies all resolved IPs are safe and returns the first safe candidate."""
    safe = first_safe_ip(ips)
    if not safe:
        raise SSRFBlockedError(f"SSRF guard blocked unvetted or internal IP set: {ips}")
    return safe


__all__ = [
    "SSRFBlockedError",
    "_PinnedHTTPTransport",
    "_PinnedNetworkBackend",
    "first_safe_ip",
    "verify_safe_ips",
]
