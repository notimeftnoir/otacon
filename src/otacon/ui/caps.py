"""What the terminal in front of us can actually render.

One axis: whether the stream can carry the designed glyph set. Colour is left
to Rich and to Textual, which both detect it well and honour ``NO_COLOR``;
``ui.tokens.get_theme`` turns that variable into the ``mono`` palette so the
HTML report and the triage console honour it too.

Nothing here raises. A terminal that answers nothing gets the conservative
answer, because the failure mode we are avoiding — a risk bar rendering as a
row of '?' — is silent, and a silent visual failure is the one nobody reports.
"""

from __future__ import annotations

import os
import sys
from enum import Enum


class GlyphLevel(str, Enum):
    """How adventurous we may be with codepoints."""

    FULL = "full"
    """Block elements, arrows, box drawing — the designed look."""

    ASCII = "ascii"
    """Nothing above U+007F. Degraded, but never tofu."""


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip().lower()


def glyph_level(encoding: str | None = None) -> GlyphLevel:
    """Whether the stream can carry the designed glyph set.

    ``OTACON_ASCII`` forces the fallback for anyone whose font is missing the
    block elements even though the encoding would carry them — which no
    amount of probing can detect from this side of the terminal.
    """
    if _env("OTACON_ASCII"):
        return GlyphLevel.ASCII
    enc = (encoding or getattr(sys.stdout, "encoding", None) or "").lower().replace("-", "")
    # Only the Unicode encodings are trusted. A legacy codepage cannot carry
    # U+2588 at all, and cli.main re-encodes to UTF-8 where it can.
    return GlyphLevel.FULL if enc.startswith(("utf", "ucs")) else GlyphLevel.ASCII


__all__ = ["GlyphLevel", "glyph_level"]
