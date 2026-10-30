"""Hardened Punycode and IDNA 2008 / UTS #46 conversion utilities."""

from __future__ import annotations

import idna


def to_ace(fqdn: str) -> str | None:
    """Canonicalises an FQDN to ASCII-Compatible Encoding (Punycode / ACE) per IDNA 2008.

    Returns None if fqdn contains disallowed characters or cannot be encoded.
    """
    if not fqdn:
        return None
    try:
        return idna.encode(fqdn, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError, ValueError):
        return None


def idn_squats(homoglyph_variants: set[str]) -> set[str]:
    """Encodes non-ASCII homoglyph variants into xn-- Punycode ACE representations."""
    out: set[str] = set()
    for variant in homoglyph_variants:
        if variant.isascii():
            continue
        ace = to_ace(variant)
        if ace and ace.startswith("xn--"):
            out.add(ace)
    return out


__all__ = ["idn_squats", "to_ace"]
