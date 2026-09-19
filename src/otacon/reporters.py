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

import csv
import io
import re
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
        host = urlparse(url).hostname
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
    """Compact age string. Bands match the scoring thresholds (AGE_FRESH_DAYS / AGE_NEW_DAYS)."""
    from .scoring import AGE_FRESH_DAYS, AGE_NEW_DAYS

    label = format_age(age_days)
    if age_days is None:
        return Text(label, style="muted")
    if age_days < AGE_FRESH_DAYS:
        return Text(label, style="critical")
    if age_days < AGE_NEW_DAYS:
        return Text(label, style="warn")
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
    fresh_count = sum(1 for r in registered if r.age_days is not None and r.age_days < 7)

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


def _results_table(target: str, rows: list[DomainResult]) -> Table:
    """Builds the results table shared by the live scan view and the final report.

    Both views show the same columns for the same rows — only *when* they are
    rendered differs — so the layout lives here rather than being declared
    twice and left to drift.
    """
    title = Text()
    title.append("Otacon", style="brand")
    title.append(" · target: ")
    title.append(target, style="value")

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

    for r in sorted(rows, key=lambda r: r.risk_score, reverse=True):
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


def build_live_table(hits: list[DomainResult], domain: str) -> Table:
    """Partial results table for the live scan view — registered hits only, sorted by score.

    Designed to be passed into a rich.Live renderable alongside a Progress bar.
    """
    return _results_table(domain, hits)


def render_table(report: ScanReport, console: Console, show_safe: bool = False) -> None:
    """Renders results as a colored terminal table (Option B layout).

    Columns: Domain+technique | Risk bar | DNS | MX | SSL | HTTP
    Defensive registrations (redirect \u2192 original) are flagged with \u2691.
    """
    console.print()
    console.print(_verdict_banner(report))

    rows = report.results if show_safe else report.registered

    if not rows:
        console.print(f"[muted]  Checked {report.total_permutations} permutations.[/muted]\n")
        return

    console.print()
    console.print(_results_table(report.target, rows))

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


def aggregate_json(reports: dict[str, ScanReport]) -> str:
    """Serializes a multi-domain scan to JSON with a per-domain breakdown and summary.

    Each value under ``domains`` is the full ScanReport serialization (target, started_at,
    total_permutations, results, dns_hijack_detected) — not a bare list of DomainResult dicts.
    """
    import json
    from datetime import datetime, timezone

    payload = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "domains": {
            domain: json.loads(report.model_dump_json()) for domain, report in reports.items()
        },
        "summary": {
            "total_registered": sum(len(r.registered) for r in reports.values()),
            "critical": sum(
                1
                for r in reports.values()
                for result in r.registered
                if result.risk_level == RiskLevel.CRITICAL
            ),
            "high": sum(
                1
                for r in reports.values()
                for result in r.registered
                if result.risk_level == RiskLevel.HIGH
            ),
            "medium": sum(
                1
                for r in reports.values()
                for result in r.registered
                if result.risk_level == RiskLevel.MEDIUM
            ),
            "low": sum(
                1
                for r in reports.values()
                for result in r.registered
                if result.risk_level == RiskLevel.LOW
            ),
        },
    }
    return json.dumps(payload, indent=2)


def _verdict_banner_md(report: ScanReport) -> str:
    """Plain-text verdict line for the Markdown export."""
    registered = report.registered
    if not registered:
        return f"✓ **clean** — {report.total_permutations} permutations checked, none registered"
    threats = report.threats
    crit_count = sum(1 for r in threats if r.risk_level == RiskLevel.CRITICAL)
    mx_count = sum(1 for r in registered if r.has_mx)
    fresh_count = sum(1 for r in registered if r.age_days is not None and r.age_days < 7)
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


_FORMULA_TRIGGER_RE = re.compile(r"^\s*[=+\-@]")


def _csv_safe(value: str) -> str:
    """Neutralises spreadsheet formula injection (CWE-1236) in untrusted cells.

    ``page_title`` and ``redirects_to`` are lifted verbatim from the hostile
    lookalike's own HTTP response — a cell starting with =/+/-/@ is evaluated
    as a formula by Excel/LibreOffice/Sheets on open. Prefixing with an
    apostrophe forces the cell to be read as plain text.
    """
    if _FORMULA_TRIGGER_RE.match(value):
        return "'" + value
    return value


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
    t.append(" · ", style="muted")
    t.append(f"{len(reports) + len(errors)} domain(s)", style="value")
    t.append(" · ", style="muted")
    t.append(f"{total_registered} registered", style="value")
    t.append(" · ", style="muted")
    t.append(f"crit: {total_crit}", style="critical" if total_crit else "muted")
    t.append(" · ", style="muted")
    t.append(f"high: {total_high}", style="danger" if total_high else "muted")
    t.append(" · ", style="muted")
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


def to_csv(report: ScanReport) -> str:
    """Generates a CSV report containing all registered domains."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(
        [
            "Domain",
            "Technique",
            "Risk Level",
            "Risk Score",
            "Age Days",
            "Resolves (DNS)",
            "Has MX",
            "Has SSL",
            "HTTP Status",
            "Redirects To",
            "Page Title",
            "Likely Defensive",
            "Notes",
        ]
    )

    for r in report.registered:
        writer.writerow(
            [
                r.domain,
                r.kind.value,
                r.risk_level.value,
                r.risk_score,
                r.age_days if r.age_days is not None else "",
                r.resolves,
                r.has_mx,
                r.has_ssl,
                r.http_status if r.http_status is not None else "",
                _csv_safe(r.redirects_to or ""),
                _csv_safe(r.page_title or ""),
                r.is_likely_defensive,
                "; ".join(r.risk_reasons),
            ]
        )
    return out.getvalue()
