"""Shared input validators — keep untrusted strings from reaching the network or filesystem.

Centralised here so CLI, interactive mode, and the webhook path all enforce the
same rules instead of each module rolling its own.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

# RFC 1035-ish: labels are 1..63 chars of [a-z0-9-], must not start/end with '-'.
# We allow uppercase too (normalised later) and ACE/punycode labels (xn--...).
# Total length cap at 253 octets per RFC. Reject anything with whitespace, NULs,
# or directory separators outright — none belong in a domain.
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

# Windows reserved device names — case-insensitive, with or without extension.
_WIN_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def is_valid_domain(domain: str) -> bool:
    """True when *domain* is a syntactically plausible FQDN.

    Rejects: empty, >253 chars, control chars / whitespace, bare IPs,
    schemes, paths, or anything not RFC 1035-ish per-label.
    """
    if not domain or len(domain) > 253:
        return False
    if any(c.isspace() or ord(c) < 0x20 for c in domain):
        return False
    if "/" in domain or "\\" in domain or "@" in domain or ":" in domain:
        return False
    # Bare IPs are not impersonation targets.
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    labels = domain.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    return all(_LABEL_RE.match(label) for label in labels)


def is_safe_webhook_url(url: str) -> bool:
    """True when *url* is an http(s) endpoint that is NOT a private/loopback target.

    Defends watch-mode webhooks against SSRF: refuses cloud metadata endpoints,
    RFC1918, link-local, loopback, multicast, and reserved ranges. Hostnames
    are resolved to IPs before checking to prevent bypasses and DNS rebinding.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False

    try:
        # Resolve all IPs for the host. Port 80 is a placeholder.
        addrinfo = socket.getaddrinfo(host, 80, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False

    for _family, _, _, _, sockaddr in addrinfo:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
            
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False

    return True


def safe_relative_path(filename: str, base: str | None = None) -> str | None:
    """Returns a resolved path string when *filename* is safely inside *base* (CWD by default).

    Refuses: absolute paths, parent-dir escapes, Windows reserved device names,
    NUL bytes, and anything that resolves outside *base*. Returns None on rejection.
    """
    from pathlib import Path

    if not filename or "\x00" in filename:
        return None
    candidate = Path(filename)
    if candidate.is_absolute() or candidate.drive:
        return None
    stem = candidate.name.split(".")[0].upper()
    if stem in _WIN_RESERVED:
        return None
    base_path = Path(base).resolve() if base else Path.cwd().resolve()
    resolved = (base_path / candidate).resolve()
    try:
        resolved.relative_to(base_path)
    except ValueError:
        return None
    return str(resolved)
