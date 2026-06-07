"""Reporters — rendering scan results.

Four output formats, decoupled from the detection logic:
  - table:    interactive, colored terminal preview (rich)
  - json:     machine-readable export (integration with other tools / SIEM)
  - markdown: ready-to-paste fragment for a report/ticket
  - html:     self-contained dark-palette report (see html_report.py)

Decoupling output from logic = it's easy to add another format (CSV, etc.)
without touching the rest.
"""

from __future__ import annotations

from urllib.parse import urlparse

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from .models import DomainResult, ScanReport
from .theme import RiskLevel
from .whois import format_age

_BAR_STYLE: dict[RiskLevel, str] = {
    RiskLevel.SAFE: "ok",
    RiskLevel.LOW: "info",
    RiskLevel.MEDIUM: "warn",
    RiskLevel.HIGH: "danger",
    RiskLevel.CRITICAL: "crit.bar",
}


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
    return ", ".join(signals) or "\u2014"


def _redirect_host(url: str) -> str:
    """Extracts the hostname from a redirect URL; falls back to the raw value."""
    try:
        host = urlparse(url).netloc
        return host if host else url
    except ValueError:
        return url


def _risk_bar(score: int, style: str) -> Text:
    """8-char block bar (████░░░░) + right-justified score, coloured by style."""
    filled = max(0, min(8, round(score / 100 * 8)))
    bar = "█" * filled + "░" * (8 - filled)
    t = Text()
    t.append(bar, style=style)
    t.append(f" {score:>3}", style=style)
    return t


def _check(value: bool) -> Text:
    """Green ✓ when True, red — when False."""
    return Text("✓", style="ok") if value else Text("—", style="danger")


def _http_cell(status: int | None) -> Text:
    """HTTP status code coloured by range (2xx green, 3xx blue, 4xx dim, 5xx yellow)."""
    if status is None:
        return Text("—", style="muted")
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
    """Compact age string, styled critical (red) for domains registered within 30 days."""
    label = format_age(age_days)
    if age_days is None:
        return Text(label, style="muted")
    if age_days < 30:
        return Text(label, style="critical")
    return Text(label, style="value")


_HIGH_RISK_LEVELS = {RiskLevel.HIGH, RiskLevel.CRITICAL}


def _domain_cell(result: DomainResult) -> Text:
    """Domain name + dim technique subtitle. ⚑ redirect host appended when defensive.
    Page title shown for high/critical rows."""
    t = Text()
    t.append(result.domain, style="value")
    t.append("\n")
    t.append(result.kind.value, style="muted")
    if result.is_likely_defensive and result.redirects_to:
        t.append("  ⚑ → ", style="warn")
        t.append(_redirect_host(result.redirects_to), style="warn")
    if result.page_title and result.risk_level in _HIGH_RISK_LEVELS:
        t.append("\n")
        t.append(f'"{escape(result.page_title)}"', style="muted")
    return t


def _verdict_banner(report: ScanReport) -> Text:
    """One-line verdict banner: counts of critical, live MX, and freshly registered.
    Green when no threats, red when criticals exist."""
    threats = report.threats
    registered = report.registered

    if not registered:
        t = Text()
        t.append("✓ clean", style="ok")
        t.append(
            f" — {report.total_permutations} permutations checked, none registered",
            style="muted",
        )
        return t

    crit_count = sum(1 for r in threats if r.risk_level == RiskLevel.CRITICAL)
    mx_count = sum(1 for r in registered if r.has_mx)
    fresh_count = sum(
        1 for r in registered if r.age_days is not None and r.age_days < 7
    )

    t = Text()
    if crit_count:
        t.append("⚠ ", style="critical")
    else:
        t.append("● ", style="warn")

    t.append(f"{len(registered)} registered", style="value")
    t.append(" · ", style="muted")
    t.append(f"crit: {crit_count}", style="critical" if crit_count else "muted")
    t.append(" · ", style="muted")
    t.append(f"mx: {mx_count}", style="danger" if mx_count else "muted")
    t.append(" · ", style="muted")
    t.append(f"fresh <7d: {fresh_count}", style="critical" if fresh_count else "muted")
    return t


def build_live_table(hits: list[DomainResult], domain: str) -> Table:
    """Partial results table for the live scan view — registered hits only, sorted by score.

    Designed to be passed into a rich.Live renderable alongside a Progress bar.
    """
    title = Text()
    title.append("Otacon", style="brand")
    title.append(" · target: ")
    title.append(domain, style="value")

    table = Table(
        title=title,
        title_justify="left",
        header_style="field",
        expand=True,
        border_style="brand.dim",
        show_lines=False,
    )
    table.add_column("Domain", no_wrap=False, min_width=30)
    table.add_column("Risk", width=14)
    table.add_column("Age", width=6, justify="right")
    table.add_column("DNS", width=5, justify="center")
    table.add_column("MX", width=5, justify="center")
    table.add_column("SSL", width=5, justify="center")
    table.add_column("HTTP", width=7, justify="center")

    for r in sorted(hits, key=lambda r: r.risk_score, reverse=True):
        table.add_row(
            _domain_cell(r),
            _risk_bar(r.risk_score, _BAR_STYLE[r.risk_level]),
            _age_cell(r.age_days),
            _check(r.resolves),
            _check(r.has_mx),
            _check(r.has_ssl),
            _http_cell(r.http_status),
        )

    return table


def render_table(report: ScanReport, console: Console, show_safe: bool = False) -> None:
    """Renders results as a colored terminal table (Option B layout).

    Columns: Domain+technique | Risk bar | DNS | MX | SSL | HTTP
    Defensive registrations (redirect \u2192 original) are flagged with \u2691.
    """
    console.print()
    console.print(_verdict_banner(report))

    rows = report.results if show_safe else report.registered

    if not rows:
        console.print(
            f"[muted]  Checked {report.total_permutations} permutations.[/muted]\n"
        )
        return

    rows = sorted(rows, key=lambda r: r.risk_score, reverse=True)

    title = Text()
    title.append("Otacon", style="brand")
    title.append(" \u00b7 target: ")
    title.append(report.target, style="value")

    table = Table(
        title=title,
        title_justify="left",
        header_style="field",
        expand=True,
        border_style="brand.dim",
        show_lines=False,
    )
    table.add_column("Domain", no_wrap=False, min_width=30)
    table.add_column("Risk", width=14)
    table.add_column("Age", width=6, justify="right")
    table.add_column("DNS", width=5, justify="center")
    table.add_column("MX", width=5, justify="center")
    table.add_column("SSL", width=5, justify="center")
    table.add_column("HTTP", width=7, justify="center")

    for r in rows:
        table.add_row(
            _domain_cell(r),
            _risk_bar(r.risk_score, _BAR_STYLE[r.risk_level]),
            _age_cell(r.age_days),
            _check(r.resolves),
            _check(r.has_mx),
            _check(r.has_ssl),
            _http_cell(r.http_status),
        )

    console.print()
    console.print(table)

    threats = report.threats
    crit = sum(1 for r in threats if r.risk_level == RiskLevel.CRITICAL)
    high = sum(1 for r in threats if r.risk_level == RiskLevel.HIGH)
    med = sum(1 for r in threats if r.risk_level == RiskLevel.MEDIUM)
    defensive = sum(1 for r in rows if r.is_likely_defensive)

    footer = Text()
    footer.append(
        f"Permutations: {report.total_permutations} \u00b7 "
        f"registered: {len(report.registered)} \u00b7 ",
        style="value",
    )
    footer.append(f"med: {med}", style="warn")
    footer.append(" \u00b7 ", style="muted")
    footer.append(f"high: {high}", style="danger")
    footer.append(" \u00b7 ", style="muted")
    footer.append(f"crit: {crit}", style="critical")
    if defensive:
        footer.append("    \u2691 = likely defensive (redirects to original)", style="warn")
    console.print(footer)
    console.print()


def to_json(report: ScanReport) -> str:
    """Serializes the full report to JSON (all fields, including reasons)."""
    return report.model_dump_json(indent=2)


def _verdict_banner_md(report: ScanReport) -> str:
    """Plain-text verdict line for the Markdown export."""
    registered = report.registered
    if not registered:
        return f"✓ **clean** — {report.total_permutations} permutations checked, none registered"
    threats = report.threats
    crit_count = sum(1 for r in threats if r.risk_level == RiskLevel.CRITICAL)
    mx_count = sum(1 for r in registered if r.has_mx)
    fresh_count = sum(
        1 for r in registered if r.age_days is not None and r.age_days < 7
    )
    icon = "⚠" if crit_count else "●"
    return (
        f"{icon} **{len(registered)} registered** · "
        f"crit: {crit_count} · mx: {mx_count} · fresh <7d: {fresh_count}"
    )


def to_markdown(report: ScanReport) -> str:
    """Generates a Markdown report — ready to paste into a ticket/issue."""
    lines: list[str] = [
        "# Otacon — domain impersonation report",
        "",
        _verdict_banner_md(report),
        "",
        f"**Target:** `{report.target}`  ",
        f"**Date:** {report.started_at:%Y-%m-%d %H:%M %Z}  ",
        f"**Permutations checked:** {report.total_permutations}  ",
        f"**Registered variants:** {len(report.registered)}",
        "",
    ]

    threats = report.threats
    if not threats:
        lines.append("No suspicious registered variants detected.")
        return "\n".join(lines)

    lines += [
        "## Detected threats",
        "",
        "| Domain | Type | Risk | Signals |",
        "|---|---|---|---|",
    ]
    for r in threats:
        lines.append(
            f"| `{r.domain}` | {r.kind.value} | "
            f"{r.risk_score} ({r.risk_level.value}) | {_signals(r)} |"
        )

    return "\n".join(lines)
