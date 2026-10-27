"""Web content analysis, sanitization, and fingerprinting utilities.

Provides ReDoS-free HTML parsing, credential form heuristics, and MurmurHash3 favicon hashing.
"""

from __future__ import annotations

import base64
import html
import unicodedata
from html.parser import HTMLParser
from urllib.parse import urljoin

_TITLE_MAX = 80
_MAX_BODY_BYTES = 65536

_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})
_CF_ALLOWED = frozenset("\u200c\u200d\u200e\u200f")
_CREDENTIAL_FIELD_NAMES = frozenset(
    {
        "pass",
        "pwd",
        "password",
        "passwd",
        "user_password",
        "auth_pass",
        "access_token",
        "secret",
    }
)


def _strip_unsafe_chars(text: str) -> str:
    """Strips control, format, and line separator characters preventing terminal injection."""
    return "".join(
        ch for ch in text if ch in _CF_ALLOWED or unicodedata.category(ch) not in _UNSAFE_CATEGORIES
    )


class _SafeHeadParser(HTMLParser):
    """Streaming, linear-time HTML parser for title, favicon, and login form indicators."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title: bool = False
        self.title_parts: list[str] = []
        self.favicon_url: str | None = None
        self.has_login_form: bool = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag_lower == "title":
            self.in_title = True
        elif tag_lower == "link":
            rel_str = attr_dict.get("rel", "").lower()
            rel_tokens = rel_str.split()
            if "icon" in rel_tokens or "shortcut icon" in rel_str:
                href = attr_dict.get("href", "").strip()
                if href and not self.favicon_url:
                    self.favicon_url = href
        elif tag_lower == "input":
            input_type = attr_dict.get("type", "").lower().strip()
            input_name = attr_dict.get("name", "").lower().strip()
            if input_type == "password" or input_name in _CREDENTIAL_FIELD_NAMES:
                self.has_login_form = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)


def _parse_title(body: str) -> str | None:
    """Extracts, cleans, and bounds <title> text from an HTML snippet."""
    if not body:
        return None
    parser = _SafeHeadParser()
    try:
        parser.feed(body[:_MAX_BODY_BYTES])
    except Exception:
        return None
    raw = "".join(parser.title_parts).strip()
    if not raw:
        return None
    cleaned = _strip_unsafe_chars(html.unescape(" ".join(raw.split())))
    return cleaned[:_TITLE_MAX] if cleaned else None


def detect_login_form(body: str) -> bool:
    """Returns True if the HTML body contains an input field for credentials or passwords."""
    if not body:
        return False
    parser = _SafeHeadParser()
    try:
        parser.feed(body[:_MAX_BODY_BYTES])
    except Exception:
        return False
    return parser.has_login_form


def extract_favicon_url(base_url: str, html_body: str) -> str:
    """Extracts the favicon URL from HTML <link> tag or returns default /favicon.ico."""
    if not html_body:
        return str(urljoin(base_url, "/favicon.ico"))
    parser = _SafeHeadParser()
    try:
        parser.feed(html_body[:_MAX_BODY_BYTES])
    except Exception:
        return str(urljoin(base_url, "/favicon.ico"))
    if parser.favicon_url:
        return str(urljoin(base_url, parser.favicon_url))
    return str(urljoin(base_url, "/favicon.ico"))


def mmh3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3_x86_32 pure-Python implementation returning signed 32-bit int."""
    length = len(data)
    nblocks = length // 4
    h1 = seed
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for i in range(0, nblocks * 4, 4):
        k1 = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = ((h1 * 5) + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4 :]
    k1 = 0
    tlen = len(tail)
    if tlen >= 3:
        k1 ^= tail[2] << 16
    if tlen >= 2:
        k1 ^= tail[1] << 8
    if tlen >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    if h1 >= 0x80000000:
        return h1 - 0x100000000
    return h1


def shodan_favicon_hash(raw_bytes: bytes) -> int:
    """Computes the standard Shodan MurmurHash3 favicon hash with RFC 2045 base64 encoding."""
    if not raw_bytes:
        return 0
    b64 = base64.encodebytes(raw_bytes)
    return mmh3_32(b64)


__all__ = [
    "_MAX_BODY_BYTES",
    "_TITLE_MAX",
    "_SafeHeadParser",
    "_parse_title",
    "_strip_unsafe_chars",
    "detect_login_form",
    "extract_favicon_url",
    "mmh3_32",
    "shodan_favicon_hash",
]
