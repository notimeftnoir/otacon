"""Favicon fingerprint, compatible with Shodan's ``http.favicon.hash``.

Phishing kits copy the real site's favicon byte for byte, so a lookalike
serving the target's exact icon is a clone even when its title differs. The
hash is Shodan's (MurmurHash3 x86_32 of the base64-encoded bytes), so an
analyst can pivot from one lookalike to every server running the same kit:
``http.favicon.hash:<value>``. Pure stdlib; no mmh3 dependency for 25 lines.
"""

from __future__ import annotations

import base64

_C1, _C2, _MASK = 0xCC9E2D51, 0x1B873593, 0xFFFFFFFF

# Leading bytes of the image formats browsers accept as a favicon. A 200 with
# an HTML body (soft 404, parking page) is not an icon and must not be hashed.
_MAGIC = (b"\x00\x00\x01\x00", b"\x89PNG", b"GIF8", b"\xff\xd8\xff", b"<svg", b"<?xml", b"RIFF")


def _rotl(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & _MASK


def _mix(k: int) -> int:
    return (_rotl((k * _C1) & _MASK, 15) * _C2) & _MASK


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 as a signed int, the value mmh3.hash() returns."""
    h = seed
    end = len(data) & ~3
    for i in range(0, end, 4):
        h ^= _mix(int.from_bytes(data[i : i + 4], "little"))
        h = (_rotl(h, 13) * 5 + 0xE6546B64) & _MASK
    tail = data[end:]
    if tail:
        h ^= _mix(int.from_bytes(tail, "little"))
    h ^= len(data)
    h = ((h ^ (h >> 16)) * 0x85EBCA6B) & _MASK
    h = ((h ^ (h >> 13)) * 0xC2B2AE35) & _MASK
    h ^= h >> 16
    return h - (1 << 32) if h & 0x80000000 else h


def looks_like_icon(data: bytes) -> bool:
    """True when *data* starts like an image a browser would show as a favicon."""
    return data.lstrip()[:5].lower().startswith((b"<svg", b"<?xml")) or data.startswith(_MAGIC)


def shodan_hash(data: bytes) -> int:
    """Shodan's favicon hash: murmur3 of base64 with a newline every 76 chars."""
    return murmur3_32(base64.encodebytes(data))
