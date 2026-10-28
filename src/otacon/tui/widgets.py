"""Pure presentation helpers shared by the TUI screens.

Separated from the screens so a row's risk bar, flag string and signal
checklist can be asserted without mounting an application.
"""

from __future__ import annotations

from rich.text import Text

from ..core.models import DomainResult, ScanReport
from ..core.types import RiskLevel
from ..utils.theme import (
    GLYPH_DEFENSIVE,
    GRADIENT,
    LOGO_DOTS_BOT,
    LOGO_DOTS_TOP,
    SPOOF_INDEX,
    TAGLINE,
    WORDMARK,
    gradient_color,
)

# Semantic colours, matching OTACON_THEME. Textual markup takes hex directly.
LEVEL_COLOR: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "#ff5f5f",
    RiskLevel.HIGH: "#ff8f5f",
    RiskLevel.MEDIUM: "#ffd700",
    RiskLevel.LOW: "#5fafff",
    RiskLevel.SAFE: "#5fd700",
}

# Digit -> level, for the 1..5 filter keys. Ordered worst-first so the key that
# is easiest to reach gives the most urgent view.
FILTER_KEYS: dict[str, RiskLevel] = {
    "1": RiskLevel.CRITICAL,
    "2": RiskLevel.HIGH,
    "3": RiskLevel.MEDIUM,
    "4": RiskLevel.LOW,
    "5": RiskLevel.SAFE,
}

BAR_WIDTH = 8


def wordmark(spoof: bool = True) -> Text:
    """OTACON in the brand gradient, with the Cyrillic homoglyph picked out in red.

    The wordmark carries the tool's whole idea: the O at SPOOF_INDEX is U+041E,
    not the Latin letter it reads as. Showing it stained is the one-glance
    explanation of what the tool looks for.
    """
    out = Text()
    last = len(WORDMARK) - 1
    for i, ch in enumerate(WORDMARK):
        if spoof and i == SPOOF_INDEX:
            out.append(ch, style="bold #ff5f87")
        else:
            out.append(ch, style=f"bold {gradient_color(i / last)}")
    return out


def logo(tagline: bool = True) -> Text:
    """The three-line radar wordmark used on the start screen."""
    out = Text()
    out.append(f" {LOGO_DOTS_TOP}\n", style=GRADIENT[0])
    out.append("   ")
    out.append_text(wordmark())
    out.append("\n")
    out.append(f" {LOGO_DOTS_BOT}", style="#00875f")
    if tagline:
        out.append(f"  {TAGLINE}", style="#8a8a8a")
    return out


def risk_bar(score: int) -> str:
    """Eight-cell density bar; the same ramp the console reporter uses."""
    filled = max(0, min(BAR_WIDTH, round(score / 100 * BAR_WIDTH)))
    return "█" * filled + "░" * (BAR_WIDTH - filled)


def badges(r: DomainResult) -> str:
    """Compact marker string for the flags that change how a row is treated."""
    marks: list[str] = []
    if r.dnsbl_listed:
        marks.append("DBL")
    if r.favicon_matches_target:
        marks.append("FAVICON")
    if r.has_login_form:
        marks.append("LOGIN")
    if r.has_mx and r.is_mail_spoofable:
        marks.append("SPOOF")
    if r.is_sinkhole:
        marks.append("SINKHOLE")
    elif r.is_parked:
        marks.append("PARKED")
    if r.is_likely_defensive:
        marks.append(GLYPH_DEFENSIVE)
    return " ".join(marks)


def signals(r: DomainResult) -> str:
    """DNS / MX / SSL / HTTP presence, as a fixed-order checklist."""
    parts = [
        ("DNS", r.resolves),
        ("MX", r.has_mx),
        ("SSL", r.has_ssl),
    ]
    out = [name if ok else "·" * len(name) for name, ok in parts]
    out.append(str(r.http_status) if r.http_status is not None else "···")
    return " ".join(out)


def level_counts(report: ScanReport) -> dict[RiskLevel, int]:
    """Counts registered results per risk level, for the masthead tally."""
    counts = dict.fromkeys(LEVEL_COLOR, 0)
    for r in report.results:
        if r.is_registered:
            counts[r.risk_level] += 1
    return counts


__all__ = [
    "BAR_WIDTH",
    "FILTER_KEYS",
    "LEVEL_COLOR",
    "badges",
    "level_counts",
    "logo",
    "risk_bar",
    "signals",
    "wordmark",
]
