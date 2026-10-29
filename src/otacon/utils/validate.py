"""Domain and filesystem path validation utilities.

Protects against SSRF, directory traversal, ReDoS, and malformed network inputs.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

# RFC 1035 label format: 1-63 chars [a-z0-9-], cannot start or end with a hyphen.
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

_WIN_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def normalize_domain(value: str) -> str:
    """Canonicalises a domain: strips whitespace, lowercases, removes 'www.' and trailing dots."""
    return value.strip().lower().removeprefix("www.").rstrip(".")


def parse_domain_list(content: str) -> set[str]:
    """Parses exclusion/whitelist file content into normalised domain names."""
    out: set[str] = set()
    for line in content.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("#") or not trimmed:
            continue
        entry = normalize_domain(trimmed)
        if entry:
            out.add(entry)
    return out


def is_valid_domain(domain: str) -> bool:
    """Validates domain syntax against RFC 1035 and length boundaries."""
    if not domain or len(domain) > 253:
        return False
    if any(c.isspace() or ord(c) < 0x20 for c in domain):
        return False
    if "/" in domain or "\\" in domain or "@" in domain or ":" in domain:
        return False
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    labels = domain.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    return all(_LABEL_RE.match(label) for label in labels)


def first_safe_ip(ips: list[str]) -> str | None:
    """Returns the first safe public IP, or None if any IP in the set is private or invalid."""
    safe_ip: str | None = None
    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (
            not ip.is_global
            or ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return None
        if safe_ip is None:
            safe_ip = ip_str
    return safe_ip


def parse_redirect(url: str) -> tuple[str, str] | None:
    """Safely extracts (hostname, scheme) from an HTTP redirect Location header."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    return (parsed.hostname or "").lower().rstrip("."), parsed.scheme


def redirect_host(url: str) -> str:
    """The hostname a redirect points at, falling back to the raw value.

    Both reporters need this and both had their own copy; the fallback matters
    because a Location header is whatever the remote server sent, and an
    unparseable one is still worth showing rather than dropping.
    """
    parsed = parse_redirect(url)
    if parsed is None:
        return url
    return parsed[0] or url


def safe_relative_path(filename: str, base: str | None = None) -> str | None:
    """Validates that a path is strictly relative and contained within base directory."""
    if not filename or "\x00" in filename:
        return None
    if re.match(r"^[A-Za-z]:", filename):
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


def safe_cli_path(filename: str) -> str | None:
    """Validates CLI paths, allowing absolute or relative paths without directory escapes."""
    if not filename or "\x00" in filename:
        return None
    candidate = Path(filename)
    stem = candidate.name.split(".")[0].upper()
    if stem in _WIN_RESERVED:
        return None
    try:
        return str(candidate.resolve())
    except Exception:
        return None
