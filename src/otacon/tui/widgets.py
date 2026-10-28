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
    """OTACON with the Cyrillic homoglyph picked out by weight.

    The wordmark carries the tool's whole idea: the O at SPOOF_INDEX is U+041E,
    not the Latin letter it reads as. It is marked by brightness rather than by
    hue, so the mark reads the same under ``mono``, ``NO_COLOR`` and a
    greyscale screenshot — and does not compete with the severity colours,
    which are the only thing in this interface that earns a hue.
    """
    from ..ui.caps import glyph_level
    from ..ui.glyphs import degrade
    from ..utils.theme import SPOOF_INDEX, WORDMARK

    pal = _palette(palette)
    level = glyph_level()
    out = Text()
    for i, ch in enumerate(WORDMARK):
        style = f"bold {pal.strong}" if spoof and i == SPOOF_INDEX else pal.muted
        out.append(degrade(ch, level), style=style)
    return out


def logo(tagline: bool = True, palette: Palette | None = None) -> Text:
    """The three-line brand mark used on the start screen."""
    from ..ui.caps import glyph_level
    from ..ui.glyphs import degrade
    from ..utils.theme import HOMOGLYPH, LOGO_SWEEP, SPOOF_INDEX, TAGLINE

    pal = _palette(palette)
    level = glyph_level()
    out = Text()
    out.append(f"{degrade(LOGO_SWEEP, level)}\n", style=pal.dim)
    out.append_text(wordmark(palette=pal))
    out.append("\n")
    pointer = f"{' ' * SPOOF_INDEX}{degrade('↑', level)} {HOMOGLYPH}"
    out.append(pointer, style=pal.dim)
    if tagline:
        out.append(f" {degrade('·', level)} {TAGLINE}", style=pal.dim)
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
    "DISTRIBUTION_WIDTH",
    "FILTER_KEYS",
    "LEVELS_DESC",
    "LEVEL_COLOR",
    "badges",
    "band_cell",
    "distribution",
    "gutter",
    "level_color",
    "level_counts",
    "logo",
    "risk_bar",
    "signals",
    "tally",
    "wordmark",
]


DISTRIBUTION_WIDTH = 36


def distribution(
    report: ScanReport, palette: Palette | None = None, width: int = DISTRIBUTION_WIDTH
) -> Text:
    """Proportional severity bar plus its legend, for the overview screen.

    The same picture the console reporter's verdict card draws, in the same
    density glyphs the table's gutter uses, so a reader who learns the ramp
    once can read it on every surface.
    """
    pal = _palette(palette)
    counts = level_counts(report)
    total = max(sum(counts.values()), 1)
    bar, legend = Text(), Text()
    for level in LEVELS_DESC:
        if not counts[level]:
            continue
        tone = pal.tone(level)
        bar.append(tone.sigil * max(1, round(counts[level] / total * width)), style=tone.fg)
        legend.append(f"{tone.sigil} ", style=tone.fg)
        # "harmless" rather than "safe", matching the console's verdict card:
        # one vocabulary across surfaces is the whole point of ui/copy.py.
        label = "harmless" if level is RiskLevel.SAFE else level.value
        legend.append(f"{counts[level]} {label}   ", style=pal.body)
    out = Text()
    out.append_text(bar)
    out.append("\n")
    out.append_text(legend)
    return out
