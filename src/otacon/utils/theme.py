"""Color palette, UI glyphs, and styling utilities for terminal and report interfaces."""

from __future__ import annotations

from rich.color import Color
from rich.text import Text
from rich.theme import Theme

from ..core.types import RiskLevel

OTACON_THEME = Theme(
    {
        "brand": "bold #00d7af",
        "brand.dim": "#00875f",
        "info": "#5fafff",
        "muted": "dim #8a8a8a",
        "ok": "bold #5fd700",
        "warn": "bold #ffd700",
        "danger": "bold #ff5f5f",
        "critical": "bold white on #870000",
        "crit.bar": "#ff0000",
        "field": "bold #afafaf",
        "value": "#ffffff",
        "url": "underline #5fafff",
        "spoof": "bold #ff5f87",
    }
)

GRADIENT = ("#00d7af", "#00c0d0", "#00a8e8", "#5f8fff")


def gradient_color(t: float, stops: tuple[str, ...] = GRADIENT) -> str:
    """Hex colour at position t (0..1) along stops, linearly interpolated."""
    t = min(max(t, 0.0), 1.0) * (len(stops) - 1)
    i = min(int(t), len(stops) - 2)
    a = Color.parse(stops[i]).get_truecolor()
    b = Color.parse(stops[i + 1]).get_truecolor()
    f = t - i
    r, g, bl = (round(x + (y - x) * f) for x, y in zip(a, b, strict=True))
    return f"#{r:02x}{g:02x}{bl:02x}"


def gradient(text: str, bold: bool = True) -> Text:
    """Colours text character by character along the brand gradient."""
    out = Text()
    last = max(len(text) - 1, 1)
    for i, ch in enumerate(text):
        out.append(ch, style=f"{'bold ' if bold else ''}{gradient_color(i / last)}")
    return out


SAFE_GLYPHS = frozenset(
    "○●"
    "░▒▓█"
    "»"
    "✓✗"
    "⚠"
    "→←"
    "►•"
    "О"  # noqa: RUF001
    "·—…›─"  # noqa: RUF001
)

GLYPH_DEFENSIVE = "»"
LOGO_DOTS_TOP = "● ● ● ○ ○ ○"
LOGO_DOTS_BOT = "○ ○ ○ ● ● ●"
WORDMARK = "OTACОN"  # noqa: RUF001
SPOOF_INDEX = 4
TAGLINE = "domain impersonation detector"


def _wordmark_markup() -> str:
    """WORDMARK as Rich markup with gradient letters and Cyrillic homoglyph in red."""
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
