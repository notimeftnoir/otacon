"""Reporters — rendering scan results.

Three output formats, decoupled from the detection logic:
  - table:    interactive, colored terminal preview (rich)
  - json:     machine-readable export (integration with other tools / SIEM)
  - markdown: ready-to-paste fragment for a report/ticket

Decoupling output from logic = it's easy to add another format (CSV, HTML)
without touching the rest.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from .models import DomainResult, ScanReport
from .theme import RiskLevel


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


def render_table(report: ScanReport, console: Console, show_safe: bool = False) -> None:
    """Renders results as a colored terminal table.

    By default shows only registered variants — unregistered permutations are
    noise (there are hundreds). show_safe=True shows everything.
    """
    rows = report.results if show_safe else report.registered

    if not rows:
        console.print(
            "\n[ok]\u2713 No registered impersonating variants detected.[/ok]"
        )
        console.print(
            f"[muted]  Checked {report.total_permutations} permutations.[/muted]\n"
        )
        return

    rows = sorted(rows, key=lambda r: r.risk_score, reverse=True)

    table = Table(
        title=f"[brand]Otacon[/brand] \u00b7 target: [value]{report.target}[/value]",
        title_justify="left",
        header_style="field",
        expand=True,
        border_style="brand.dim",
    )
    table.add_column("", width=3, justify="center")  # risk icon
    table.add_column("Domain", style="value", no_wrap=True)
    table.add_column("Type", style="muted")
    table.add_column("Risk", justify="right")
    table.add_column("Signals", style="muted")

    for r in rows:
        lvl = r.risk_level
        table.add_row(
            f"[{lvl.style}]{lvl.icon}[/{lvl.style}]",
            r.domain,
            r.kind.value,
            f"[{lvl.style}]{r.risk_score:>3} {lvl.value}[/{lvl.style}]",
            _signals(r),
        )

    console.print()
    console.print(table)

    # Summary below the table.
    threats = report.threats
    crit = sum(1 for r in threats if r.risk_level == RiskLevel.CRITICAL)
    high = sum(1 for r in threats if r.risk_level == RiskLevel.HIGH)
    console.print(
        f"[muted]Permutations: {report.total_permutations} \u00b7 "
        f"registered: {len(report.registered)} \u00b7 "
        f"[/muted][danger]high: {high}[/danger] "
        f"[critical] critical: {crit} [/critical]\n"
    )


def to_json(report: ScanReport) -> str:
    """Serializes the full report to JSON (all fields, including reasons)."""
    return report.model_dump_json(indent=2)


def to_markdown(report: ScanReport) -> str:
    """Generates a Markdown report — ready to paste into a ticket/issue."""
    lines: list[str] = [
        "# Otacon — domain impersonation report",
        "",
        f"**Target:** `{report.target}`  ",
        f"**Date:** {report.started_at:%Y-%m-%d %H:%M UTC}  ",
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
