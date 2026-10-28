"""Brand marks, and the live view of the active palette.

The colours themselves moved to :mod:`otacon.ui.tokens`; this module is what
the rest of the codebase already imported, so it stays as the brand surface
(wordmark, banner) plus a thin, backwards-compatible view of whichever theme
is active.

The wordmark is the tool's whole argument in six characters: the O at
``SPOOF_INDEX`` is U+041E, Cyrillic, not the Latin letter it reads as. Showing
it stained is the one-glance explanation of what Otacon looks for.
"""

from __future__ import annotations

from rich.text import Text
from rich.theme import Theme

from ..core.types import RiskLevel
from ..ui.caps import ColorDepth, GlyphLevel, color_depth, glyph_level
from ..ui.emit import gradient_color as _gradient_at
from ..ui.emit import gradient_for, rich_theme
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

GRADIENT: tuple[str, ...] = MIDNIGHT.gradient


def gradient_color(t: float, stops: tuple[str, ...] = GRADIENT) -> str:
    """Hex colour at position t (0..1) along stops, linearly interpolated."""
    return _gradient_at(t, stops)


def gradient(text: str, bold: bool = True) -> Text:
    """Colours text character by character along the brand gradient.

    The ramp is whatever the terminal can actually resolve: a four-stop 24-bit
    gradient quantises to one flat colour below truecolor, which made the
    wordmark look broken rather than merely plainer.
    """
    stops = gradient_for(_palette, color_depth())
    out = Text()
    last = max(len(text) - 1, 1)
    for i, ch in enumerate(text):
        out.append(ch, style=f"{'bold ' if bold else ''}{_gradient_at(i / last, stops)}")
    return out


GLYPH_DEFENSIVE = "»"
LOGO_DOTS_TOP = "● ● ● ○ ○ ○"
LOGO_DOTS_BOT = "○ ○ ○ ● ● ●"
WORDMARK = "OTACОN"  # noqa: RUF001  — the fifth character is U+041E
SPOOF_INDEX = 4
TAGLINE = "domain impersonation detector"


def _wordmark_markup(palette: Palette, stops: tuple[str, ...]) -> str:
    """WORDMARK as Rich markup: gradient letters, Cyrillic homoglyph stained."""
    last = len(WORDMARK) - 1
    spoof = palette.tone(RiskLevel.CRITICAL).fg
    return "".join(
        f"[bold {spoof}]{ch}[/]"
        if i == SPOOF_INDEX
        else f"[bold {_gradient_at(i / last, stops)}]{ch}[/]"
        for i, ch in enumerate(WORDMARK)
    )


def banner(palette: Palette | None = None, depth: ColorDepth | None = None) -> str:
    """The three-line brand banner, as Rich markup, for the given palette."""
    pal = palette or _palette
    stops = gradient_for(pal, depth if depth is not None else color_depth())
    glyphs = glyph_level()
    top = degrade(LOGO_DOTS_TOP, glyphs)
    bot = degrade(LOGO_DOTS_BOT, glyphs)
    arrow = degrade("←", glyphs)
    return (
        f"\n [bold {pal.brand}]{top}[/]\n"
        f"   {_wordmark_markup(pal, stops)}   "
        f"[dim {pal.muted}]{arrow} [0x041E] homoglyph target[/]\n"
        f" [{pal.brand_dim}]{bot}[/]  [dim {pal.muted}]{TAGLINE}[/]\n"
    )


BANNER = banner(MIDNIGHT, ColorDepth.TRUECOLOR)
"""The default-theme banner, kept as a constant for the modules that import it."""

__all__ = [
    "BANNER",
    "GLYPH_DEFENSIVE",
    "GRADIENT",
    "LOGO_DOTS_BOT",
    "LOGO_DOTS_TOP",
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
    "gradient",
    "gradient_color",
    "set_palette",
]
