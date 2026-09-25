"""Consistent color palette and styles for the entire CLI.

Single source of truth for colors. Every module imports from here, so a
theme change in one place propagates across the whole interface.

Palette tuned for dark terminals (most common among pentesters), with
risk semantics based on intuition: red = threat, green = safe, yellow = caution.
"""

from __future__ import annotations

from enum import Enum

from rich.theme import Theme

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
    }
)


class RiskLevel(str, Enum):
    """Risk levels. String values make JSON serialization trivial."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def style(self) -> str:
        """Maps a risk level to a rich style (from OTACON_THEME)."""
        return {
            RiskLevel.SAFE: "ok",
            RiskLevel.LOW: "info",
            RiskLevel.MEDIUM: "warn",
            RiskLevel.HIGH: "danger",
            RiskLevel.CRITICAL: "critical",
        }[self]

    @property
    def icon(self) -> str:
        """Status icon — works even without colors (e.g. when piped to a file).

        A density ramp, not circles with partial or full fill (U+25D0-U+25D5,
        plus U+25CF for critical) that would read more naturally: those are
        missing from the fonts people run a terminal in. See SAFE_GLYPHS.
        """
        return {
            RiskLevel.SAFE: "○",
            RiskLevel.LOW: "░",
            RiskLevel.MEDIUM: "▒",
            RiskLevel.HIGH: "▓",
            RiskLevel.CRITICAL: "█",
        }[self]

    @property
    def rank(self) -> int:
        """Numeric rank for threshold comparisons (0 = safe … 4 = critical)."""
        return {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    @classmethod
    def from_score(cls, score: int) -> RiskLevel:
        """Maps a raw numeric score (0-100) to a risk level."""
        if score >= 80:
            return cls.CRITICAL
        if score >= 60:
            return cls.HIGH
        if score >= 35:
            return cls.MEDIUM
        if score >= 15:
            return cls.LOW
        return cls.SAFE


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
    "→"  # → arrow
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
_LOGO_TOP = f" [brand]{LOGO_DOTS_TOP}[/]"
_LOGO_MID = "   [brand]OTACON[/]"
_LOGO_BOT = f" [brand]{LOGO_DOTS_BOT}[/]  [muted]domain impersonation detector[/]"
BANNER = f"\n{_LOGO_TOP}\n{_LOGO_MID}\n{_LOGO_BOT}\n"
