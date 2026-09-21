"""Shared input validators — keep untrusted strings from reaching the network or filesystem.

Centralised here so the CLI, interactive mode, and the resolver all enforce the
same rules instead of each module rolling its own.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# RFC 1035-ish: labels are 1..63 chars of [a-z0-9-], must not start/end with '-'.
# We allow uppercase too (normalised later) and ACE/punycode labels (xn--...).
# Total length cap at 253 octets per RFC. Reject anything with whitespace, NULs,
# or directory separators outright — none belong in a domain.
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

# Windows reserved device names — case-insensitive, with or without extension.
_WIN_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def normalize_domain(value: str) -> str:
    """Canonicalises a domain string for validation and comparison.

    Trims surrounding whitespace, lowercases, drops a leading ``www.``, then
    strips a trailing root dot. Centralised so every entry point (CLI,
    interactive mode, permutation exclusions) normalises identically instead of
    re-deriving the chain per call site.

    Whitelist entries go through the same ``www.`` stripping as targets: they are
    only ever compared against permutation output, and no technique emits a
    ``www.``-prefixed FQDN (``_www_merge`` produces ``wwwexample``), so keeping
    the prefix would make ``--exclude www.example.net`` match nothing at all.
    """
    return value.strip().lower().removeprefix("www.").rstrip(".")


def parse_domain_list(content: str) -> set[str]:
    """Parses whitelist/exclusion file *content* into a set of normalised domains.

    Blank lines and ``#`` comments are dropped; every surviving line goes through
    ``normalize_domain``. Shared by ``--exclude-file``, interactive mode's
    ``whitelist.txt``, and the defensive-registration writer, so a file this
    function accepts is read back identically by all three — otherwise a stray
    ``\\r`` or a capitalised entry reads as a new domain and the writer appends a
    duplicate on every run.
    """
    out: set[str] = set()
    for line in content.splitlines():
        if line.strip().startswith("#"):
            continue
        entry = normalize_domain(line)
        if entry:
            out.add(entry)
    return out


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


def first_safe_ip(ips: list[str]) -> str | None:
    """Returns the first address in *ips* that is safe to connect to, or None.

    "Safe" excludes private/loopback/link-local (which covers cloud metadata
    endpoints)/multicast/reserved/unspecified ranges. Any unsafe address in
    *ips* poisons the whole batch — a host answering with a mix of public and
    internal addresses is itself a DNS-rebinding-style red flag, not just a
    case of "pick the good one and ignore the rest".

    Used by the resolver's HTTP/TLS probing, which connects to
    attacker-influenced hosts and must not let a hostile DNS answer route
    the connection at an internal service.
    """
    safe_ip: str | None = None
    for ip_str in ips:
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
            return None
        if safe_ip is None:
            safe_ip = ip_str
    return safe_ip


def parse_redirect(url: str) -> tuple[str, str] | None:
    """Splits a ``Location`` header into ``(hostname, scheme)``, or None if unparseable.

    *hostname* comes back lowercased with the root dot stripped, and is ``""``
    for a relative Location (``/login``); *scheme* is ``""`` when absent.

    A Location header is verbatim attacker-controlled output from a lookalike
    host, and ``urlparse`` raises ValueError on a malformed IPv6 authority
    (``http://[evil``) rather than degrading. Every consumer goes through here
    so one hostile redirect cannot take down a scan, a score, or a report.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    return (parsed.hostname or "").lower().rstrip("."), parsed.scheme


def safe_relative_path(filename: str, base: str | None = None) -> str | None:
    """Returns a resolved path string when *filename* is safely inside *base* (CWD by default).

    Refuses: absolute paths, parent-dir escapes, Windows reserved device names,
    NUL bytes, and anything that resolves outside *base*. Returns None on rejection.
    """
    from pathlib import Path

    if not filename or "\x00" in filename:
        return None
    # Reject Windows-style drive letters cross-platform (Path.drive is empty on POSIX).
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
