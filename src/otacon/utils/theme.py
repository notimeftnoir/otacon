"""The brand mark, and the live view of the active palette.

The colours live in :mod:`otacon.ui.tokens`; this module is the brand surface
plus a thin, backwards-compatible view of whichever theme is active.

The wordmark is the whole product in six characters: the O at ``SPOOF_INDEX``
is U+041E, Cyrillic, not the Latin letter it reads as. The letters stay tight
so the illusion holds: letter-spaced, the mark stops fooling anyone, and being
fooled at a glance is the point.

The mark carries no hue of its own. Severity is the only thing in this
interface that earns colour, and a logo competing with it was noise; the
homoglyph is picked out by weight and brightness instead, which also means the
mark survives ``mono``, ``NO_COLOR``, a greyscale screenshot and a printed
page unchanged.
"""

from __future__ import annotations

from rich.theme import Theme

from ..core.types import RiskLevel
from ..ui.caps import ColorDepth, GlyphLevel, color_depth, glyph_level
from ..ui.emit import rich_theme
from ..ui.glyphs import SAFE as SAFE_GLYPHS
from ..ui.glyphs import degrade
from ..ui.tokens import MIDNIGHT, Palette, get_theme

# The active palette. Mutable because `--theme` is resolved after import:
# the CLI builds its Console at module scope, long before argv is parsed.
_palette: Palette = MIDNIGHT


def active_palette() -> Palette:
    """The palette every surface should currently be drawing with."""
    return _palette


def set_palette(name: str | None) -> Palette:
    """Switches the active palette, returning it. Unknown names keep the default."""
    global _palette
    _palette = get_theme(name)
    return _palette


OTACON_THEME: Theme = rich_theme(MIDNIGHT)
"""The default Rich theme. ``--theme`` pushes a different one onto the console."""

GLYPH_DEFENSIVE = "»"
WORDMARK = "OTACОN"  # noqa: RUF001  — the fifth character is U+041E
SPOOF_INDEX = 4
HOMOGLYPH = "U+041E"
TAGLINE = "domain impersonation detector"

LOGO_SWEEP = "░▒▓█▓▒░"
"""A scan passing over the name.

Replaces the two rows of dots the mark used to carry. Same idea — marks above
the wordmark, sweeping — in the density ramp the rest of the interface now
uses for severity, so the tool has one visual language rather than two.
"""


def _marker_row(glyphs: GlyphLevel) -> str:
    """The pointer line: an arrow under the homoglyph, then what it is."""
    arrow = degrade("↑", glyphs)
    separator = degrade("·", glyphs)
    return f"{' ' * (1 + SPOOF_INDEX)}{arrow} {HOMOGLYPH} {separator} {TAGLINE}"


def wordmark_markup(palette: Palette, glyphs: GlyphLevel | None = None) -> str:
    """WORDMARK as Rich markup, with the homoglyph picked out by weight.

    The letters degrade like everything else: U+041E cannot be drawn on a
    terminal that only has ASCII, and leaving it there would show the reader
    a replacement character in the brand mark itself.
    """
    level = glyphs if glyphs is not None else glyph_level()
    return "".join(
        f"[bold {palette.strong}]{degrade(ch, level)}[/]"
        if i == SPOOF_INDEX
        else f"[{palette.muted}]{degrade(ch, level)}[/]"
        for i, ch in enumerate(WORDMARK)
    )


def banner(palette: Palette | None = None, glyphs: GlyphLevel | None = None) -> str:
    """The three-line brand mark, as Rich markup, for the given palette."""
    pal = palette or _palette
    level = glyphs if glyphs is not None else glyph_level()
    sweep = degrade(LOGO_SWEEP, level)
    return (
        f"\n [{pal.dim}]{sweep}[/]\n"
        f" {wordmark_markup(pal, level)}\n"
        f" [{pal.dim}]{_marker_row(level)[1:]}[/]\n"
    )


BANNER = banner(MIDNIGHT, GlyphLevel.FULL)
"""The default-theme banner, kept as a constant for the modules that import it."""

__all__ = [
    "BANNER",
    "GLYPH_DEFENSIVE",
    "HOMOGLYPH",
    "LOGO_SWEEP",
    "OTACON_THEME",
    "SAFE_GLYPHS",
    "SPOOF_INDEX",
    "TAGLINE",
    "WORDMARK",
    "ColorDepth",
    "GlyphLevel",
    "Palette",
    "RiskLevel",
    "active_palette",
    "banner",
    "color_depth",
    "degrade",
    "glyph_level",
    "set_palette",
    "wordmark_markup",
]
