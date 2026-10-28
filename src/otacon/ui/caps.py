"""What the terminal in front of us can actually render.

Two axes, resolved independently because terminals mix them freely: a modern
emulator over SSH may carry 24-bit colour on a latin-1 stream, and a Windows
console may be fully UTF-8 at sixteen colours.

Nothing here raises. A terminal that answers nothing gets the conservative
answer, because the failure mode we are avoiding — a wordmark collapsing into
one flat colour, a risk bar rendering as a row of '?' — is silent, and a
silent visual failure is the one nobody reports.
"""

from __future__ import annotations

import os
import sys
from enum import Enum

from .tokens import Palette


class ColorDepth(str, Enum):
    """How many colours the stream can carry."""

    TRUECOLOR = "truecolor"
    EIGHT_BIT = "256"
    BASIC = "16"
    NONE = "none"


class GlyphLevel(str, Enum):
    """How adventurous we may be with codepoints."""

    FULL = "full"
    """Block elements, arrows, box drawing — the designed look."""

    ASCII = "ascii"
    """Nothing above U+007F. Degraded, but never tofu."""


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip().lower()


def color_depth(stream_is_tty: bool = True) -> ColorDepth:
    """Best guess at the stream's colour depth.

    ``NO_COLOR`` wins over everything — it is a user instruction, not a
    capability — and a stream that is not a terminal is treated as colourless
    so redirected output stays diffable.
    """
    if _env("NO_COLOR"):
        return ColorDepth.NONE
    if not stream_is_tty:
        return ColorDepth.NONE

    forced = _env("OTACON_COLOR")
    if forced in {d.value for d in ColorDepth}:
        return ColorDepth(forced)

    term = _env("TERM")
    if term in {"dumb", ""} and not _env("COLORTERM"):
        return ColorDepth.NONE
    if _env("COLORTERM") in {"truecolor", "24bit"}:
        return ColorDepth.TRUECOLOR
    if "256" in term or "truecolor" in term:
        return ColorDepth.EIGHT_BIT
    return ColorDepth.BASIC


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


def gradient_stops(palette: Palette, depth: ColorDepth) -> tuple[str, ...]:
    """The wordmark ramp, degraded to what *depth* can actually show.

    A four-stop 24-bit ramp quantises to a single colour on a 16-colour
    terminal, which is why the logo used to look broken there rather than
    merely plainer: every letter landed on the same cyan. Below 8-bit we stop
    pretending and return one stop, so the wordmark reads as a deliberate
    solid rather than a failed gradient.
    """
    if depth is ColorDepth.NONE:
        return (palette.strong,)
    if depth is ColorDepth.BASIC:
        return (palette.brand,)
    if depth is ColorDepth.EIGHT_BIT:
        # 256-colour cubes cannot resolve four neighbouring teals; the two
        # ends stay distinguishable and the ramp still reads as a ramp.
        return (palette.gradient[0], palette.gradient[-1])
    return palette.gradient


__all__ = ["ColorDepth", "GlyphLevel", "color_depth", "glyph_level", "gradient_stops"]
