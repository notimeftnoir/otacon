"""Pure presentation helpers shared by the TUI screens.

Separated from the screens so a row's gutter, flag string and signal checklist
can be asserted without mounting an application.

Colours come from the active palette rather than from literals here, so the
triage console themes with the rest of the tool.
"""

from __future__ import annotations

from rich.table import Table
from rich.text import Text
from textual.widgets._toggle_button import ToggleButton

from ..core.models import DomainResult, ScanReport
from ..core.types import RiskLevel
from ..ui.copy import FLAGS
from ..ui.copy import flags as flag_names
from ..ui.copy import signals as _signals
from ..ui.tokens import Palette
from ..utils.theme import active_palette, glyph

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


def sigil(level: RiskLevel, palette: Palette | None = None) -> str:
    """The severity glyph for *level*, degraded to what the terminal can draw.

    Every severity mark in the console goes through here. Without it `--ascii`
    reached the brand mark and nothing else, so a terminal that cannot render
    U+2588 was given a logo it could read above a table it could not.
    """
    from ..ui.glyphs import degrade
    from ..utils.theme import active_glyphs

    return degrade(_palette(palette).tone(level).sigil, active_glyphs())


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
    from ..ui.glyphs import degrade
    from ..utils.theme import SPOOF_INDEX, WORDMARK, active_glyphs

    pal = _palette(palette)
    level = active_glyphs()
    out = Text()
    for i, ch in enumerate(WORDMARK):
        style = f"bold {pal.strong}" if spoof and i == SPOOF_INDEX else pal.muted
        out.append(degrade(ch, level), style=style)
    return out


def logo(tagline: bool = True, palette: Palette | None = None) -> Text:
    """The three-line brand mark used on the start screen."""
    from ..ui.glyphs import degrade
    from ..utils.theme import HOMOGLYPH, LOGO_SWEEP, SPOOF_INDEX, TAGLINE, active_glyphs

    pal = _palette(palette)
    level = active_glyphs()
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
    from ..ui.glyphs import degrade
    from ..utils.theme import active_glyphs

    level = active_glyphs()
    filled = max(0, min(BAR_WIDTH, round(score / 100 * BAR_WIDTH)))
    return degrade("█", level) * filled + degrade("░", level) * (BAR_WIDTH - filled)


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
    return Text(sigil(level, pal), style=pal.tone(level).fg)


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


def ascii_toggle(button: ToggleButton) -> ToggleButton:
    """Returns *button* with Textual's own marks degraded for this terminal.

    Textual paints a toggle as BUTTON_LEFT + BUTTON_INNER + BUTTON_RIGHT, each
    read per instance when it renders, so they can be degraded without touching
    the framework class. The brackets are half-block glyphs with no stand-in in
    the degrade table — dropping them would leave the mark with no container at
    all — so ASCII mode gets the conventional parentheses instead.
    """
    from ..ui.caps import GlyphLevel
    from ..utils.theme import active_glyphs

    if active_glyphs() is GlyphLevel.FULL:
        return button
    button.BUTTON_LEFT, button.BUTTON_RIGHT = "(", ")"
    button.BUTTON_INNER = glyph(button.BUTTON_INNER) or "*"
    return button


def badges(r: DomainResult) -> str:
    """Compact marker string for the flags that change how a row is treated."""
    return " ".join(FLAGS[name].short for name in flag_names(r))


def signals(r: DomainResult) -> str:
    """The presence checklist, degraded to what this terminal can draw."""
    from ..utils.theme import active_glyphs

    return _signals(r, active_glyphs())


def level_counts(report: ScanReport) -> dict[RiskLevel, int]:
    """Counts registered results per risk level, for the masthead tally."""
    counts = dict.fromkeys(RiskLevel, 0)
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
            t.append(f"{sigil(level, pal)} ", style=tone.fg)
        t.append(f"{counts[level]:<4}", style="bold " + pal.strong)
    t.append(f"  {report.total_permutations} checked ", style=pal.muted)
    if report.degraded:
        # Name the layer that actually failed: degraded covers probe errors too,
        # so reporting a DNS percentage here could print " 0% DNS failed ".
        if report.probe_failures and report.probe_failure_ratio >= report.dns_failure_ratio:
            note = f"{round(report.probe_failure_ratio * 100)}% of checks failed"
        else:
            note = f"{round(report.dns_failure_ratio * 100)}% DNS failed"
        t.append(glyph(f" ⚠ {note} "), style=f"bold {pal.tone(RiskLevel.MEDIUM).fg}")
    return t


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
        mark = sigil(level, pal)
        bar.append(mark * max(1, round(counts[level] / total * width)), style=tone.fg)
        legend.append(f"{mark} ", style=tone.fg)
        # "harmless" rather than "safe", matching the console's verdict card:
        # one vocabulary across surfaces is the whole point of ui/copy.py.
        label = "harmless" if level is RiskLevel.SAFE else level.value
        legend.append(f"{counts[level]} {label}   ", style=pal.body)
    out = Text()
    out.append_text(bar)
    out.append("\n")
    out.append_text(legend)
    return out


LIVE_ROWS = 6


def live_hits(
    hits: list[DomainResult], palette: Palette | None = None, limit: int = LIVE_ROWS
) -> Table:
    """The riskiest findings so far, for the scan in flight.

    `otacon scan` has always drawn this from inside the engine while it ran.
    The triage console could not, so the surface people actually use showed a
    bar and a number through the one part of a scan worth watching.
    """
    pal = _palette(palette)
    table = Table.grid(padding=(0, 2))
    table.add_column(width=5, no_wrap=True)
    table.add_column(width=28, no_wrap=True)
    table.add_column(ratio=1, overflow="ellipsis")
    for r in sorted(hits, key=lambda h: (-h.risk_score, h.domain))[:limit]:
        tone = pal.tone(r.risk_level)
        mark = Text(sigil(r.risk_level, pal), style=tone.fg)
        mark.append(f" {r.risk_score:>3}", style=tone.fg)
        table.add_row(
            mark,
            Text(r.domain, style=f"bold {pal.strong}"),
            Text(badges(r), style=tone.fg),
        )
    return table


def scan_tally(hits: int, dangerous: int, palette: Palette | None = None) -> Text:
    """Running count for the scan header."""
    pal = _palette(palette)
    t = Text()
    if not hits:
        t.append("nothing registered yet", style=pal.dim)
        return t
    t.append(f"{hits} registered", style=f"bold {pal.strong}")
    if dangerous:
        t.append("  ", style=pal.dim)
        t.append(f"{dangerous} dangerous", style=f"bold {pal.tone(RiskLevel.HIGH).fg}")
    return t


__all__ = [
    "BAR_WIDTH",
    "DISTRIBUTION_WIDTH",
    "FILTER_KEYS",
    "LEVELS_DESC",
    "LIVE_ROWS",
    "ascii_toggle",
    "badges",
    "band_cell",
    "distribution",
    "gutter",
    "level_color",
    "level_counts",
    "live_hits",
    "logo",
    "risk_bar",
    "scan_tally",
    "sigil",
    "signals",
    "tally",
    "wordmark",
]
