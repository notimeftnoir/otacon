"""Consistent color palette and styles for the entire CLI.

Single source of truth for colors. Every module imports from here, so a
theme change in one place propagates across the whole interface.

Palette tuned for dark terminals (most common among pentesters), with
risk semantics based on intuition: red = threat, green = safe, yellow = caution.
"""

from __future__ import annotations

from rich.color import Color
from rich.text import Text
from rich.theme import Theme

from .core.types import RiskLevel

# Semantic palette. Names describe MEANING, not color, so re-theming
# does not require changes in the logic.
OTACON_THEME = Theme(
    {
        "brand": "bold #00d7af",  # brand accent (teal)
        "brand.dim": "#00875f",
        "info": "#5fafff",  # neutral information
        "muted": "dim #8a8a8a",  # secondary text
        "ok": "bold #5fd700",  # safe / no threat
        "warn": "bold #ffd700",  # suspicious
        "danger": "bold #ff5f5f",  # high risk
        "critical": "bold white on #870000",  # critical
        "crit.bar": "#ff0000",  # solid red block for the risk-scale bar
        "field": "bold #afafaf",  # field labels
        "value": "#ffffff",
        "url": "underline #5fafff",
        "spoof": "bold #ff5f87",  # the planted homoglyph in the wordmark
    }
)

# Brand gradient, teal to sky blue. Truecolor stops; Rich downsamples them on
# 256- and 16-colour terminals, so no capability check is needed here.
GRADIENT = ("#00d7af", "#00c0d0", "#00a8e8", "#5f8fff")


def gradient_color(t: float, stops: tuple[str, ...] = GRADIENT) -> str:
    """Hex colour at position *t* (0..1) along *stops*, linearly interpolated."""
    t = min(max(t, 0.0), 1.0) * (len(stops) - 1)
    i = min(int(t), len(stops) - 2)
    a = Color.parse(stops[i]).get_truecolor()
    b = Color.parse(stops[i + 1]).get_truecolor()
    f = t - i
    r, g, bl = (round(x + (y - x) * f) for x, y in zip(a, b, strict=True))
    return f"#{r:02x}{g:02x}{bl:02x}"


def gradient(text: str, bold: bool = True) -> Text:
    """*text* coloured character by character along the brand gradient."""
    out = Text()
    last = max(len(text) - 1, 1)
    for i, ch in enumerate(text):
        out.append(ch, style=f"{'bold ' if bold else ''}{gradient_color(i / last)}")
    return out


# Every glyph the UI prints has to live in this set.
#
# The limit is the terminal *font*, not the encoding: a codepoint the font has
# no glyph for comes out as "?" or tofu however clean the UTF-8 is, and the
# Segoe UI Symbol fallback that would cover it is a Windows Terminal feature
# conhost does not have.
#
# So the bar is: present in the monospace fonts themselves. These are, across
# Consolas, Cascadia Mono, Courier New, Lucida Console and JetBrains Mono —
# except U+2713/U+2717/U+26A0, which only the modern two carry and which stay
# because a check mark has no readable substitute. The tempting shapes that no
# monospace font here ships, and are therefore banned: U+2B21/U+2B22
# (hexagons), U+25D0-U+25D5 (partial circles), U+2691 (flag), U+25C6/U+25C7
# (diamonds), U+21B3 (arrow hook), U+2605 (star). (U+25CF, a full circle, is
# NOT banned — it stays as the banner's grid dot, see SAFE_GLYPHS below.)
#
# tests/test_theme.py enforces the set — extend it only with a glyph you have
# checked against those fonts.
SAFE_GLYPHS = frozenset(
    "○●"  # ○ ● grid dots
    "░▒▓█"  # ░ ▒ ▓ █ density ramp / risk bar
    "»"  # » defensive redirect marker
    "✓✗"  # ✓ ✗ check marks
    "⚠"  # ⚠ warning
    "→←"  # → ← arrows
    "►•"  # ► • step marker and bullet (WGL4, in every font listed above)
    "О"  # noqa: RUF001 — Cyrillic capital O (U+041E) homoglyph target in banner
    "·—…›─"  # noqa: RUF001 - punctuation and rules; the last two are U+203A, U+2500
)

# Marks a variant the brand registered defensively: variant » original.
# Replaces the U+2691 flag, which no common terminal font ships.
GLYPH_DEFENSIVE = "»"

# Banner — dot grid. The two markup-free rows are exported so html_report.py's
# (differently-styled, HTML rather than rich-markup) logo can build from the
# same glyphs instead of hardcoding its own copy that could drift out of sync.
LOGO_DOTS_TOP = "● ● ● ○ ○ ○"
LOGO_DOTS_BOT = "○ ○ ○ ● ● ●"
# The wordmark carries its own spoof: the fifth letter is Cyrillic, exactly
# the kind of lookalike the tool exists to catch.
WORDMARK = "OTACОN"  # noqa: RUF001
SPOOF_INDEX = 4
TAGLINE = "domain impersonation detector"


def _wordmark_markup() -> str:
    """WORDMARK as Rich markup: gradient letters, the one at SPOOF_INDEX in red."""
    last = len(WORDMARK) - 1
    return "".join(
        f"[spoof]{ch}[/]" if i == SPOOF_INDEX else f"[bold {gradient_color(i / last)}]{ch}[/]"
        for i, ch in enumerate(WORDMARK)
    )


_LOGO_TOP = f" [brand]{LOGO_DOTS_TOP}[/]"
_LOGO_MID = f"   {_wordmark_markup()}   [muted]← [0x041E] homoglyph target[/muted]"
_LOGO_BOT = f" [brand.dim]{LOGO_DOTS_BOT}[/]  [muted]{TAGLINE}[/]"
BANNER = f"\n{_LOGO_TOP}\n{_LOGO_MID}\n{_LOGO_BOT}\n"

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
    "RiskLevel",
    "gradient",
    "gradient_color",
]
