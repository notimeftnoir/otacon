"""Compatibility shim for web fingerprinting and MurmurHash3 utilities."""

from __future__ import annotations

from .net.content import (
    detect_login_form,
    extract_favicon_url,
    mmh3_32,
    shodan_favicon_hash,
)

__all__ = [
    "detect_login_form",
    "extract_favicon_url",
    "mmh3_32",
    "shodan_favicon_hash",
]
