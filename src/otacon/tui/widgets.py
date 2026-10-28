"""Pure presentation helpers shared by the TUI screens.

Separated from the screens so a row's gutter, flag string and signal checklist
can be asserted without mounting an application.

Colours come from the active palette rather than from literals here, so the
triage console themes with the rest of the tool.
"""

from __future__ import annotations

from rich.text import Text

from ..core.models import DomainResult, ScanReport
from ..core.types import RiskLevel
from ..ui.copy import FLAGS
from ..ui.tokens import MIDNIGHT, Palette
from ..utils.theme import active_palette

# Kept as a module constant for the callers that want the default palette
# without threading one through. Runtime rendering uses level_color().
LEVEL_COLOR: dict[RiskLevel, str] = {level: MIDNIGHT.tone(level).fg for level in RiskLevel}

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

# Worst first, which is both the reading order of the tally and the order the
# table sorts in.
LEVELS_DESC: tuple[RiskLevel, ...] = (
    RiskLevel.CRITICAL,
    RiskLevel.HIGH,
    RiskLevel.MEDIUM,
    RiskLevel.LOW,
    RiskLevel.SAFE,
)


def _palette(palette: Palette | None = None) -> Palette:
    return palette or active_palette()


def level_color(level: RiskLevel, palette: Palette | None = None) -> str:
    """The foreground for *level* in the active (or given) palette."""
    return _palette(palette).tone(level).fg


def wordmark(spoof: bool = True, palette: Palette | None = None) -> Text:
    """OTACON in the brand gradient, with the Cyrillic homoglyph picked out.

    The wordmark carries the tool's whole idea: the O at SPOOF_INDEX is U+041E,
    not the Latin letter it reads as. Showing it stained is the one-glance
    explanation of what the tool looks for.
    """
    from ..ui.caps import color_depth
    from ..ui.emit import gradient_color, gradient_for
    from ..utils.theme import SPOOF_INDEX, WORDMARK

    pal = _palette(palette)
    stops = gradient_for(pal, color_depth())
    out = Text()
    last = len(WORDMARK) - 1
    for i, ch in enumerate(WORDMARK):
        if spoof and i == SPOOF_INDEX:
            out.append(ch, style=f"bold {pal.tone(RiskLevel.CRITICAL).fg}")
        else:
            out.append(ch, style=f"bold {gradient_color(i / last, stops)}")
    return out


def logo(tagline: bool = True, palette: Palette | None = None) -> Text:
    """The three-line radar wordmark used on the start screen."""
    from ..utils.theme import LOGO_DOTS_BOT, LOGO_DOTS_TOP, TAGLINE

    pal = _palette(palette)
    out = Text()
    out.append(f" {LOGO_DOTS_TOP}\n", style=pal.brand)
    out.append("   ")
    out.append_text(wordmark(palette=pal))
    out.append("\n")
    out.append(f" {LOGO_DOTS_BOT}", style=pal.brand_dim)
    if tagline:
        out.append(f"  {TAGLINE}", style=pal.muted)
    return out


def risk_bar(score: int) -> str:
    """Eight-cell density bar; the same ramp the console reporter uses."""
    filled = max(0, min(BAR_WIDTH, round(score / 100 * BAR_WIDTH)))
    return "█" * filled + "░" * (BAR_WIDTH - filled)


def gutter(level: RiskLevel, palette: Palette | None = None) -> Text:
    """One cell of severity, as a density glyph.

    This replaces the eight-cell bar in the table's leading column. Stacked
    over the thirty-odd rows a real scan produces — whose scores often sit
    within ten points of each other — that bar painted one uniform block and
    separated nothing, while costing the width that DOMAIN and FLAGS needed.
    A single glyph gives a crisp edge per row, and because the ramp is ordered
    by ink it still reads with no colour at all.
    """
    pal = _palette(palette)
    return Text(pal.tone(level).sigil, style=pal.tone(level).fg)


def band_cell(level: RiskLevel, first_of_band: bool, palette: Palette | None = None) -> Text:
    """The band label, printed once at the top of each severity run.

    Severity was previously implicit in a colour the eye had to compare across
    rows. Naming each run where it starts is what tells a reader where "act
    now" ends and the noise begins.
    """
    if not first_of_band:
        return Text("")
    pal = _palette(palette)
    tone = pal.tone(level)
    return Text(tone.band, style=f"bold {tone.fg}")


def badges(r: DomainResult) -> str:
    """Compact marker string for the flags that change how a row is treated."""
    marks: list[str] = []
    if r.dnsbl_listed:
        marks.append(FLAGS["dnsbl"].short)
    if r.favicon_matches_target:
        marks.append(FLAGS["favicon"].short)
    if r.has_login_form:
        marks.append(FLAGS["login"].short)
    if r.has_mx and r.is_mail_spoofable:
        marks.append(FLAGS["spoof"].short)
    if r.is_sinkhole:
        marks.append(FLAGS["sinkhole"].short)
    elif r.is_parked:
        marks.append(FLAGS["parked"].short)
    if r.is_likely_defensive:
        # Was a bare "»", the one marker in this column with no way to find out
        # what it meant.
        marks.append(FLAGS["defensive"].short)
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


def tally(report: ScanReport, labelled: bool = True, palette: Palette | None = None) -> Text:
    """The masthead counters.

    Labelled by default. The bare glyph form it used to carry was unreadable
    to anyone who had not already learned the ramp — there was no legend
    anywhere on screen — so the labels are the default and the glyphs are the
    fallback for a terminal too narrow to hold them.
    """
    pal = _palette(palette)
    counts = level_counts(report)
    t = Text()
    for level in LEVELS_DESC:
        tone = pal.tone(level)
        if labelled:
            t.append(f"{tone.band} ", style=f"bold {tone.fg}")
        else:
            t.append(f"{tone.sigil} ", style=tone.fg)
        t.append(f"{counts[level]:<4}", style="bold " + pal.strong)
    t.append(f"  {report.total_permutations} checked ", style=pal.muted)
    if report.degraded:
        pct = round(report.dns_failure_ratio * 100)
        t.append(f" ⚠ {pct}% DNS failed ", style=f"bold {pal.tone(RiskLevel.MEDIUM).fg}")
    return t


__all__ = [
    "BAR_WIDTH",
    "FILTER_KEYS",
    "LEVELS_DESC",
    "LEVEL_COLOR",
    "badges",
    "band_cell",
    "gutter",
    "level_color",
    "level_counts",
    "logo",
    "risk_bar",
    "signals",
    "tally",
    "wordmark",
]
