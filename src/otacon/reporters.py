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
from datetime import UTC
from typing import TYPE_CHECKING

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ._validate import parse_redirect
from .models import DomainResult, ScanReport
from .theme import GLYPH_DEFENSIVE, RiskLevel
from .whois import format_age

if TYPE_CHECKING:
    from .check import CheckResult

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
    return ", ".join(signals) or "—"


def _redirect_host(url: str) -> str:
    """Extracts the hostname from a redirect URL; falls back to the raw value."""
    parsed = parse_redirect(url)
    if parsed is None:
        return url
    return parsed[0] or url


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


_POINTS_RE = re.compile(r"\s*\(\+(\d+)\)$")


def _why(result: DomainResult, limit: int = 2) -> str:
    """The *limit* highest-scoring reasons in plain words, without point tags."""
    scored = []
    for reason in result.risk_reasons:
        m = _POINTS_RE.search(reason)
        if m and not reason.startswith("technique"):
            scored.append((int(m.group(1)), reason[: m.start()]))
    scored.sort(key=lambda p: p[0], reverse=True)
    return " · ".join(text for _, text in scored[:limit])


def _domain_cell(result: DomainResult) -> Text:
    """Domain name + dim technique subtitle and the main reasons it scored.
    Redirect host appended when defensive. Page title shown for high/critical rows."""
    t = Text()
    t.append(result.domain, style="bold white")
    t.append("\n")
    t.append(result.kind.value, style="brand.dim")
    why = _why(result) if result.risk_level != RiskLevel.SAFE else ""
    if why:
        t.append(f" · {why}", style="muted")
    if result.is_likely_defensive and result.redirects_to:
        t.append(f"  {GLYPH_DEFENSIVE} ", style="warn")
        t.append(_redirect_host(result.redirects_to), style="warn")
    if result.page_title and result.risk_level in _HIGH_RISK_LEVELS:
        t.append("\n")
        # No escape() here: Text.append takes literal text and never parses
        # console markup, so escaping would render the backslash itself —
        # a hostile title "[b] sale" would show up as "\[b] sale".
        t.append(f'"{result.page_title}"', style="muted")
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

    from .scoring import AGE_FRESH_DAYS, count_fresh

    crit_count = sum(1 for r in threats if r.risk_level == RiskLevel.CRITICAL)
    mx_count = sum(1 for r in registered if r.has_mx)
    fresh_count = count_fresh(registered)

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
    t.append(
        f"fresh <{AGE_FRESH_DAYS}d: {fresh_count}", style="critical" if fresh_count else "muted"
    )
    return t


_LEVELS_DESC = (
    RiskLevel.CRITICAL,
    RiskLevel.HIGH,
    RiskLevel.MEDIUM,
    RiskLevel.LOW,
    RiskLevel.SAFE,
)
_DIST_WIDTH = 40


def _headline(report: ScanReport) -> tuple[str, str, str]:
    """(style, headline, explanation) in plain words for the verdict card."""
    registered = report.registered
    n, target = len(registered), report.target
    plural = "s" if n != 1 else ""
    if not registered:
        return (
            "ok",
            f"✓ All clear: none of the {report.total_permutations} lookalikes "
            f"of {target} are registered",
            "Nobody has registered a domain that imitates yours. New ones appear "
            "every day, so run this again from time to time.",
        )
    worst = max(r.risk_level.rank for r in registered)
    if worst >= RiskLevel.HIGH.rank:
        k = sum(1 for r in registered if r.risk_level.rank >= RiskLevel.HIGH.rank)
        return (
            "danger",
            f"⚠ {k} lookalike{'s' if k != 1 else ''} of {target} look{'' if k != 1 else 's'} "
            "dangerous",
            "Registered and set up like a real website or mail server. "
            "Start with the top rows of the table.",
        )
    if worst >= RiskLevel.LOW.rank:
        return (
            "warn",
            f"● {n} registered lookalike{plural} of {target}, nothing urgent",
            "They exist, but show few signs of being used for attacks yet. Worth a look.",
        )
    return (
        "ok",
        f"✓ {n} registered lookalike{plural} of {target}, all look harmless",
        "Parked pages or redirects back to your own site.",
    )


def _distribution(registered: list[DomainResult]) -> Group:
    """Stacked bar of registered lookalikes by risk level, plus its legend."""
    counts = {lvl: sum(1 for r in registered if r.risk_level == lvl) for lvl in _LEVELS_DESC}
    total = max(len(registered), 1)
    # Every non-empty level keeps at least one cell, so a lone critical
    # among fifty harmless parked domains is still visible.
    bar, legend = Text(), Text()
    for lvl in _LEVELS_DESC:
        if not counts[lvl]:
            continue
        style = _BAR_STYLE[lvl]
        bar.append(lvl.icon * max(1, round(counts[lvl] / total * _DIST_WIDTH)), style=style)
        legend.append(f"{lvl.icon} ", style=style)
        label = "harmless" if lvl == RiskLevel.SAFE else lvl.value
        legend.append(f"{counts[lvl]} {label}   ", style="value")
    return Group(bar, legend)


def _check_headline(found: CheckResult) -> tuple[str, str, str]:
    """(style, headline, explanation) for ``otacon check``, in plain words."""
    brand = found.match.brand.title() if found.match else ""
    real = found.match.official[0] if found.match else ""
    r = found.result
    if found.verdict == "official":
        return "ok", f"✓ This is the real {brand}", f"{found.host} belongs to {brand}."
    if found.verdict == "reported":
        target = f"a fake {brand} site" if brand else "a phishing site"
        return (
            "danger",
            f"⚠ Already reported as {target}",
            f"Listed by {', '.join(r.intel_sources) if r else 'a phishing feed'}. Do not use it.",
        )
    if found.verdict == "deceptive":
        return (
            "danger",
            f"⚠ A disguised link pretending to be {brand}",
            f"It does not go to {real} at all, but to {found.host}. Do not use it.",
        )
    if found.verdict == "established" and r is not None:
        return (
            "warn",
            f"● Resembles {brand}, but has existed for {format_age(r.age_days)}",
            f"Probably an unrelated business. The real one is {real}; check which you meant.",
        )
    if found.verdict == "impersonation" and r is not None:
        how = found.match.how if found.match else ""
        if not r.is_registered:
            return (
                "warn",
                f"● Imitates {brand} {how}, but nobody has registered it",
                f"Harmless right now. The real site is {real}.",
            )
        if r.risk_level.rank >= RiskLevel.HIGH.rank:
            return (
                "danger",
                f"⚠ Looks like a fake {brand} site",
                f"It imitates {real} {how} and is set up to be used. The real site is {real}.",
            )
        return (
            "warn",
            f"● Imitates {brand} {how}",
            f"Few signs of use yet, but it is not {real}. Do not log in there.",
        )
    return (
        "info",
        "No well-known brand imitated",
        "Otacon knows no brand this name copies; --brand checks against a specific one.",
    )


def check_card(found: CheckResult) -> Panel:
    """Boxed verdict for ``otacon check``: headline, meaning, notes."""
    style, headline, explanation = _check_headline(found)
    parts: list[Text] = [Text(headline, style=style), Text(explanation, style="muted")]
    for note in found.notes:
        parts.append(Text(f"• {note}", style="warn"))
    return Panel(
        Group(*parts),
        title="[field] Verdict [/field]",
        title_align="left",
        border_style=style,
        box=box.SQUARE,
        padding=(1, 2),
    )


def _verdict_card(report: ScanReport) -> Panel:
    """Boxed verdict: a plain-language headline, what it means, and the numbers."""
    style, headline, explanation = _headline(report)
    stats = Text(f"{report.total_permutations} checked · ", style="muted")
    stats.append_text(_verdict_banner(report))
    parts: list[Text | Group] = [Text(headline, style=style), Text(explanation, style="muted")]
    if report.registered:
        parts += [Text(), _distribution(report.registered), Text(), stats]
    return Panel(
        Group(*parts),
        title="[field] Verdict [/field]",
        title_align="left",
        border_style=style,
        box=box.SQUARE,
        padding=(1, 2),
    )


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
        caption_justify="left",
        caption_style="muted",
        header_style="field",
        expand=True,
        box=box.SIMPLE_HEAD,
        border_style="brand.dim",
        show_lines=False,
        leading=1,
    )
    # ratio=1: the domain and its reasons take whatever width the fixed
    # signal columns leave over.
    table.add_column("Domain", no_wrap=False, min_width=30, ratio=1)
    table.add_column("Risk", width=14)
    table.add_column("Age", width=5, justify="right")
    table.add_column("DNS", width=3, justify="center")
    table.add_column("MX", width=3, justify="center")
    table.add_column("SSL", width=3, justify="center")
    table.add_column("HTTP", width=4, justify="center")

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


def build_live_table(hits: list[DomainResult], domain: str, limit: int = 0) -> Table:
    """Partial results table for the live scan view — registered hits only, sorted by score.

    Designed to be passed into a rich.Live renderable alongside a Progress bar.
    *limit* > 0 keeps only the riskiest rows and notes how many are held back.
    """
    rows = sorted(hits, key=lambda r: r.risk_score, reverse=True)
    if limit <= 0 or len(rows) <= limit:
        return _results_table(domain, rows)
    table = _results_table(domain, rows[:limit])
    table.caption = f"+{len(rows) - limit} more · full table when the scan ends"
    return table


def render_table(report: ScanReport, console: Console, show_safe: bool = False) -> None:
    """Renders results as a colored terminal table (Option B layout).

    Columns: Domain+technique | Risk bar | DNS | MX | SSL | HTTP
    Defensive registrations (redirect → original) are flagged with GLYPH_DEFENSIVE.
    """
    console.print()
    console.print(_verdict_card(report))

    rows = report.results if show_safe else report.registered

    if not rows:
        console.print()
        return

    console.print()
    console.print(_results_table(report.target, rows))

    # The counts already live in the verdict card; only the marker needs a key.
    if any(r.is_likely_defensive for r in rows):
        console.print(
            f"[warn]{GLYPH_DEFENSIVE}[/warn] [muted]= likely defensive: redirects to your own "
            "site, probably registered by you[/muted]"
        )
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
    from datetime import datetime

    payload = {
        "scanned_at": datetime.now(UTC).isoformat(),
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
    from .scoring import AGE_FRESH_DAYS, count_fresh

    threats = report.threats
    crit_count = sum(1 for r in threats if r.risk_level == RiskLevel.CRITICAL)
    mx_count = sum(1 for r in registered if r.has_mx)
    fresh_count = count_fresh(registered)
    icon = "⚠" if crit_count else "●"
    return (
        f"{icon} **{len(registered)} registered** · "
        f"crit: {crit_count} · mx: {mx_count} · fresh <{AGE_FRESH_DAYS}d: {fresh_count}"
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
                _csv_safe(r.domain),
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
