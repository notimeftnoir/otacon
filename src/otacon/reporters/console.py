"""Rich terminal table and verdict card rendering for interactive scans."""

from __future__ import annotations

import re

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.models import DomainResult, ScanReport
from ..core.types import RiskLevel
from ..net.whois import format_age
from ..scoring.engine import count_fresh, get_age_fresh_days, get_age_new_days
from ..triage.verdict import verdict
from ..ui.caps import GlyphLevel
from ..ui.copy import FLAGS
from ..ui.copy import flags as flag_names
from ..ui.copy import signals as signal_checklist
from ..ui.glyphs import degrade
from ..utils.theme import active_glyphs, active_palette, glyph

_BAR_STYLE: dict[RiskLevel, str] = {
    RiskLevel.SAFE: "ok",
    RiskLevel.LOW: "info",
    RiskLevel.MEDIUM: "warn",
    RiskLevel.HIGH: "danger",
    RiskLevel.CRITICAL: "crit.bar",
}

_HIGH_RISK_LEVELS = {RiskLevel.HIGH, RiskLevel.CRITICAL}

# Rich draws its own frames, so `--ascii` has to reach them too: a table whose
# every glyph degrades, sitting inside a panel drawn with U+250C, is still
# unreadable on the terminal the flag exists for. SIMPLE_HEAD has no ASCII
# twin in Rich, so here is one — a borderless box with a dashed header rule.
_ASCII_SIMPLE_HEAD = box.Box(
    "    \n    \n -- \n    \n    \n    \n    \n    \n",
    ascii=True,
)


def _box(unicode_box: box.Box, ascii_box: box.Box) -> box.Box:
    """Picks the frame style the terminal can actually draw."""
    return ascii_box if active_glyphs() is GlyphLevel.ASCII else unicode_box


_POINTS_RE = re.compile(r"\s*\(\+(\d+)\)$")

_LEVELS_DESC = (
    RiskLevel.CRITICAL,
    RiskLevel.HIGH,
    RiskLevel.MEDIUM,
    RiskLevel.LOW,
    RiskLevel.SAFE,
)
_DIST_WIDTH = 40


def _signals(result: DomainResult) -> str:
    """Builds a compact signal string (DNS/MX/SSL/HTTP) for a result row."""
    signals = []
    if result.resolves:
        signals.append("DNS")
    if result.has_mx:
        signals.append("MX")
    if result.has_ssl:
        signals.append("SSL")
    if result.http_status is not None:
        signals.append(f"HTTP {result.http_status}")
    return ", ".join(signals) or glyph("—")


def _risk_bar(score: int, style: str) -> Text:
    """8-char block bar (████░░░░) + right-justified score, coloured by style."""
    level = active_glyphs()
    filled = max(0, min(8, round(score / 100 * 8)))
    bar = degrade("█", level) * filled + degrade("░", level) * (8 - filled)
    t = Text()
    t.append(bar, style=style)
    t.append(f" {score:>3}", style=style)
    return t


def _check(value: bool) -> Text:
    """Green tick when True, red dash when False."""
    level = active_glyphs()
    return (
        Text(degrade("✓", level), style="ok")
        if value
        else Text(degrade("—", level), style="danger")
    )


def _http_cell(status: int | None) -> Text:
    """HTTP status code coloured by range."""
    if status is None:
        return Text(glyph("—"), style="muted")
    if 200 <= status < 300:
        style = "ok"
    elif 300 <= status < 400:
        style = "info"
    elif 400 <= status < 500:
        style = "muted"
    else:
        style = "warn"
    return Text(str(status), style=style)


def _age_cell(age_days: int | None) -> Text:
    """Compact age string coloured by risk band."""
    label = degrade(format_age(age_days), active_glyphs())
    if age_days is None:
        return Text(label, style="muted")
    if age_days < get_age_fresh_days():
        return Text(label, style="critical")
    if age_days < get_age_new_days():
        return Text(label, style="warn")
    return Text(label, style="value")


def _why(result: DomainResult, limit: int = 2) -> str:
    """Returns top highest-scoring reasons without points."""
    scored: list[tuple[int, str]] = []
    for reason in result.risk_reasons:
        m = _POINTS_RE.search(reason)
        if m and not reason.startswith("technique"):
            scored.append((int(m.group(1)), reason[: m.start()]))
    scored.sort(key=lambda p: p[0], reverse=True)
    return glyph(" · ".join(text for _, text in scored[:limit]))


def _domain_cell(result: DomainResult) -> Text:
    """Just the name.

    The redirect target used to ride along here behind a bare "»". It wrapped
    the column onto a second line, and the Flags column already says OURS —
    which is the same claim in a word a reader can look up.
    """
    return Text(result.domain, style="bold white")


def _why_section(rows: list[DomainResult]) -> Table | None:
    """Why the dangerous rows are dangerous, at full width, after the table.

    This used to live in the domain cell, where a column two dozen characters
    wide wrapped it across three lines and turned twelve findings into a
    screen and a half. Reasons are prose; prose needs the width of the
    terminal, not the width of a column.
    """
    worrying = [r for r in rows if r.risk_level in _HIGH_RISK_LEVELS]
    if not worrying:
        return None
    grid = Table.grid(padding=(0, 2))
    grid.add_column(width=2)
    grid.add_column(width=26, no_wrap=True)
    grid.add_column(ratio=1, overflow="fold")
    for r in sorted(worrying, key=lambda x: x.risk_score, reverse=True):
        why = _why(r)
        if r.page_title:
            # The page title is a finding, so it is never degraded; only the
            # separator in front of it is chrome.
            quoted = f'"{r.page_title}"'
            why = f"{why}{glyph(' · ')}{quoted}" if why else quoted
        grid.add_row(
            Text(""),
            Text(r.domain, style="bold white"),
            Text(why or "registered and resolving", style="muted"),
        )
    return grid


def _flags_cell(result: DomainResult) -> Text:
    """The markers that change what an operator does, in the shared spelling.

    The same four-character codes the triage console prints. They used to be
    `[cloned-favicon]` here, `FAVICON` there and `cloned favicon` in the HTML,
    so a reader moving between surfaces had to work out that three spellings
    meant one thing.
    """
    names = flag_names(result)
    if not names:
        return Text("")
    style = "critical" if result.risk_level.rank >= RiskLevel.HIGH.rank else "warn"
    return Text(" ".join(FLAGS[n].short for n in names), style=style)


def _verdict_banner(report: ScanReport) -> Text:
    """One-line verdict banner summarizing registered, critical, and fresh hits."""
    threats = report.threats
    registered = report.registered

    if not registered:
        t = Text()
        t.append(f"{glyph('✓')} clean", style="ok")
        t.append(
            glyph(f" — {report.total_permutations} permutations checked, none registered"),
            style="muted",
        )
        return t

    crit_count = sum(1 for r in threats if r.risk_level == RiskLevel.CRITICAL)
    mx_count = sum(1 for r in registered if r.has_mx)
    fresh_days = get_age_fresh_days()
    fresh_count = count_fresh(registered)

    t = Text()
    level = active_glyphs()
    t.append(
        f"{degrade('⚠' if crit_count else '●', level)} ",
        style="critical" if crit_count else "warn",
    )

    t.append(f"{len(registered)} registered", style="value")
    dot = f" {degrade('·', level)} "
    t.append(dot, style="muted")
    t.append(f"crit: {crit_count}", style="critical" if crit_count else "muted")
    t.append(dot, style="muted")
    t.append(f"mx: {mx_count}", style="danger" if mx_count else "muted")
    t.append(dot, style="muted")
    t.append(f"fresh <{fresh_days}d: {fresh_count}", style="critical" if fresh_count else "muted")
    return t


def _headline(report: ScanReport) -> tuple[str, str, str]:
    """The verdict's tone, headline and explanation.

    Thin adapter over triage.verdict, which the overview screen renders too —
    the console used to own this wording, so the surface most people actually
    meet had none of it.
    """
    v = verdict(report)
    return v.tone, v.headline, v.explanation


def _distribution(registered: list[DomainResult]) -> Group:
    counts = {lvl: sum(1 for r in registered if r.risk_level == lvl) for lvl in _LEVELS_DESC}
    total = max(len(registered), 1)
    bar, legend = Text(), Text()
    for lvl in _LEVELS_DESC:
        if not counts[lvl]:
            continue
        style = _BAR_STYLE[lvl]
        mark = degrade(active_palette().tone(lvl).sigil, active_glyphs())
        bar.append(mark * max(1, round(counts[lvl] / total * _DIST_WIDTH)), style=style)
        legend.append(f"{mark} ", style=style)
        label = "harmless" if lvl == RiskLevel.SAFE else lvl.value
        legend.append(f"{counts[lvl]} {label}   ", style="value")
    return Group(bar, legend)


def _verdict_card(report: ScanReport) -> Panel:
    decision = verdict(report)
    style, headline, explanation = decision.tone, decision.headline, decision.explanation
    headline = f"{glyph(decision.marker)} {headline}"
    stats = Text(
        f"{report.total_permutations} checked {degrade('·', active_glyphs())} ", style="muted"
    )
    stats.append_text(_verdict_banner(report))
    parts: list[Text | Group] = [Text(headline, style=style), Text(explanation, style="muted")]
    if report.registered:
        parts += [Text(), _distribution(report.registered), Text(), stats]
    return Panel(
        Group(*parts),
        title="[field] Verdict [/field]",
        title_align="left",
        border_style=style,
        box=_box(box.SQUARE, box.ASCII),
        padding=(1, 2),
    )


def _results_table(target: str, rows: list[DomainResult]) -> Table:
    title = Text()
    title.append("Otacon", style="brand")
    title.append(f" {degrade('·', active_glyphs())} target: ")
    title.append(target, style="value")

    table = Table(
        title=title,
        title_justify="left",
        caption_justify="left",
        caption_style="muted",
        header_style="field",
        expand=True,
        box=_box(box.SIMPLE_HEAD, _ASCII_SIMPLE_HEAD),
        border_style="brand.dim",
        show_lines=False,
        # No leading: it separated cells that used to run to three lines
        # each. One row is one line now, and the blank between every pair
        # doubled the height of the table for nothing.
    )
    table.add_column("Risk", width=12)
    table.add_column("Domain", no_wrap=False, min_width=24, ratio=1)
    table.add_column("Tech", width=11)
    table.add_column("Age", width=5, justify="right")
    table.add_column("Signals", width=15)
    # Flags last and unbounded: it is the column that changes what an operator
    # does with a row, so it gets whatever width is left rather than being the
    # first thing squeezed.
    table.add_column("Flags")

    for r in sorted(rows, key=lambda r: r.risk_score, reverse=True):
        table.add_row(
            _risk_bar(r.risk_score, _BAR_STYLE[r.risk_level]),
            _domain_cell(r),
            Text(r.kind.value, style="brand.dim"),
            _age_cell(r.age_days),
            Text(signal_checklist(r, active_glyphs()), style="muted"),
            _flags_cell(r),
        )

    return table


def build_live_table(hits: list[DomainResult], domain: str, limit: int = 0) -> Table:
    """Builds a partial results table for the live scanning view."""
    rows = sorted(hits, key=lambda r: r.risk_score, reverse=True)
    if limit <= 0 or len(rows) <= limit:
        return _results_table(domain, rows)
    table = _results_table(domain, rows[:limit])
    table.caption = glyph(f"+{len(rows) - limit} more · full table when the scan ends")
    return table


def render_table(
    report: ScanReport, console: Console, show_safe: bool = False, top: int = 0
) -> None:
    """Renders scan results as a stylized terminal table.

    *top* caps how many rows the table prints, worst first. A busy brand
    returns a hundred registered lookalikes of which the first handful are the
    ones anybody acts on, and scrolling past the rest to reach the verdict is
    nobody's idea of a report.
    """
    console.print()
    console.print(_verdict_card(report))

    rows = report.results if show_safe else report.registered

    if not rows:
        console.print()
        return

    hidden = 0
    if top > 0 and len(rows) > top:
        rows = sorted(rows, key=lambda r: (-r.risk_score, r.domain))[:top]
        hidden = len(report.results if show_safe else report.registered) - top

    console.print()
    console.print(_results_table(report.target, rows))

    if hidden:
        console.print(
            f"[muted]+{hidden} more below the top {top} "
            f"{degrade('·', active_glyphs())} drop --top to see them all[/muted]"
        )

    reasons = _why_section(rows)
    if reasons is not None:
        console.print("[field]Why these matter[/field]")
        console.print(reasons)
        console.print()

    if any(r.is_likely_defensive for r in rows):
        console.print(
            f"[warn]{FLAGS['defensive'].short}[/warn] [muted]= {FLAGS['defensive'].meaning}[/muted]"
        )
    console.print()


def render_aggregate_summary(
    reports: dict[str, ScanReport],
    errors: list[str],
    console: Console,
) -> None:
    """Prints a multi-domain summary banner after all domains have been scanned."""
    total_registered = sum(len(r.registered) for r in reports.values())
    total_crit = sum(
        1
        for r in reports.values()
        for result in r.registered
        if result.risk_level == RiskLevel.CRITICAL
    )
    total_high = sum(
        1
        for r in reports.values()
        for result in r.registered
        if result.risk_level == RiskLevel.HIGH
    )
    total_med = sum(
        1
        for r in reports.values()
        for result in r.registered
        if result.risk_level == RiskLevel.MEDIUM
    )

    t = Text()
    t.append("\nScan complete", style="brand")
    t.append(glyph(" · "), style="muted")
    t.append(f"{len(reports) + len(errors)} domain(s)", style="value")
    t.append(glyph(" · "), style="muted")
    t.append(f"{total_registered} registered", style="value")
    t.append(glyph(" · "), style="muted")
    t.append(f"crit: {total_crit}", style="critical" if total_crit else "muted")
    t.append(glyph(" · "), style="muted")
    t.append(f"high: {total_high}", style="danger" if total_high else "muted")
    t.append(glyph(" · "), style="muted")
    t.append(f"med: {total_med}", style="warn" if total_med else "muted")
    console.print(t)

    for domain, report in reports.items():
        registered = report.registered
        crit = sum(1 for r in registered if r.risk_level == RiskLevel.CRITICAL)
        high = sum(1 for r in registered if r.risk_level == RiskLevel.HIGH)
        med = sum(1 for r in registered if r.risk_level == RiskLevel.MEDIUM)
        row = Text()
        row.append(f"  {domain:<35}", style="value")
        row.append(f"{len(registered)} hit{'s' if len(registered) != 1 else ''}", style="muted")
        if crit:
            row.append(f"  crit:{crit}", style="critical")
        if high:
            row.append(f"  high:{high}", style="danger")
        if med:
            row.append(f"  med:{med}", style="warn")
        console.print(row)

    for domain in errors:
        row = Text()
        row.append(f"  {domain:<35}", style="muted")
        row.append("ERROR", style="danger")
        console.print(row)

    console.print()


__all__ = [
    "_BAR_STYLE",
    "_DIST_WIDTH",
    "_HIGH_RISK_LEVELS",
    "_LEVELS_DESC",
    "_POINTS_RE",
    "_age_cell",
    "_check",
    "_distribution",
    "_domain_cell",
    "_flags_cell",
    "_headline",
    "_http_cell",
    "_results_table",
    "_risk_bar",
    "_signals",
    "_verdict_banner",
    "_verdict_card",
    "_why",
    "_why_section",
    "build_live_table",
    "render_aggregate_summary",
    "render_table",
]
