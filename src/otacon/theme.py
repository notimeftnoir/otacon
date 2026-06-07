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
        "brand": "bold #00d7af",          # brand accent (teal)
        "brand.dim": "#00875f",
        "info": "#5fafff",                # neutral information
        "muted": "dim #8a8a8a",           # secondary text
        "ok": "bold #5fd700",             # safe / no threat
        "warn": "bold #ffd700",           # suspicious
        "danger": "bold #ff5f5f",         # high risk
        "critical": "bold white on #870000",  # critical
        "crit.bar": "#ff0000",            # solid red block for the risk-scale bar
        "field": "bold #afafaf",          # field labels
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
        """Status icon — works even without colors (e.g. when piped to a file)."""
        return {
            RiskLevel.SAFE: "\u25cb",
            RiskLevel.LOW: "\u25d4",
            RiskLevel.MEDIUM: "\u25d1",
            RiskLevel.HIGH: "\u25d5",
            RiskLevel.CRITICAL: "\u25cf",
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


# ASCII banner — Hexagon grid with radar scanner.
_LOGO_TOP = " [brand]⬢ ⬢ ⬢ ⬡ ⬡ ⬡[/]"
_LOGO_MID = "   [brand]OTACON[/]  [brand]∴[/]"
_LOGO_BOT = " [brand]⬡ ⬡ ⬡ ⬢ ⬢ ⬢[/]  [muted]domain impersonation detector[/]"
_BAR = "[ok]█[/][info]█[/][warn]█[/][danger]█[/][crit.bar]█[/]"
_LEGEND = "[ok]safe[/] [info]low[/] [warn]med[/] [danger]high[/] [crit.bar]crit[/]"
BANNER = f"\n{_LOGO_TOP}\n{_LOGO_MID}\n{_LOGO_BOT}\n          {_BAR} {_LEGEND}\n"
