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
from ..scoring.engine import AGE_FRESH_DAYS, AGE_NEW_DAYS, count_fresh, get_age_fresh_days
from ..utils.theme import GLYPH_DEFENSIVE
from ..utils.validate import parse_redirect

_BAR_STYLE: dict[RiskLevel, str] = {
    RiskLevel.SAFE: "ok",
    RiskLevel.LOW: "info",
    RiskLevel.MEDIUM: "warn",
    RiskLevel.HIGH: "danger",
    RiskLevel.CRITICAL: "crit.bar",
}

_HIGH_RISK_LEVELS = {RiskLevel.HIGH, RiskLevel.CRITICAL}
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
    return ", ".join(signals) or "—"


def _redirect_host(url: str) -> str:
    """Extracts hostname from a redirect URL; falls back to raw value."""
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
    """HTTP status code coloured by range."""
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
    """Compact age string coloured by risk band."""
    label = format_age(age_days)
    if age_days is None:
        return Text(label, style="muted")
    if age_days < AGE_FRESH_DAYS:
        return Text(label, style="critical")
    if age_days < AGE_NEW_DAYS:
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
    return " · ".join(text for _, text in scored[:limit])


def _domain_cell(result: DomainResult) -> Text:
    """Domain name cell with badges, subtitle technique, and page title."""
    t = Text()
    t.append(result.domain, style="bold white")
    if result.is_sinkhole:
        t.append(" [sinkhole]", style="info")
    elif result.is_parked:
        t.append(" [parked]", style="muted")
    if result.dnsbl_listed:
        t.append(" [DBL]", style="critical")
    if result.favicon_matches_target:
        t.append(" [cloned-favicon]", style="critical")
    if result.has_login_form:
        t.append(" [login-form]", style="warn")
    if result.has_mx and result.is_mail_spoofable:
        t.append(" [spoofable-email]", style="warn")
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
        t.append(f'"{result.page_title}"', style="muted")
    return t


def _verdict_banner(report: ScanReport) -> Text:
    """One-line verdict banner summarizing registered, critical, and fresh hits."""
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
    fresh_days = get_age_fresh_days()
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
    t.append(f"fresh <{fresh_days}d: {fresh_count}", style="critical" if fresh_count else "muted")
    return t


def _headline(report: ScanReport) -> tuple[str, str, str]:
    registered = report.registered
    n, target = len(registered), report.target
    plural = "s" if n != 1 else ""
    if report.degraded:
        # A broken resolver and a clean brand produce the same empty result, so
        # this case must never be reported as an all-clear.
        pct = round(report.dns_failure_ratio * 100)
        return (
            "warn",
            f"⚠ Inconclusive: {pct}% of DNS lookups for {target} failed",
            (
                f"{report.dns_failures} of {report.dns_queries} lookups could not be answered, "
                "so a domain shown as unregistered may simply not have been checked. "
                "Re-run with --debug to see why, and treat these results as incomplete."
            ),
        )
    if not registered:
        return (
            "ok",
            (
                f"✓ All clear: none of the {report.total_permutations} lookalikes of "
                f"{target} are registered"
            ),
            (
                "Nobody has registered a domain that imitates yours. New ones appear every day, "
                "so run this again from time to time."
            ),
        )
    worst = max(r.risk_level.rank for r in registered)
    if worst >= RiskLevel.HIGH.rank:
        k = sum(1 for r in registered if r.risk_level.rank >= RiskLevel.HIGH.rank)
        return (
            "danger",
            (
                f"⚠ {k} lookalike{'s' if k != 1 else ''} of {target} "
                f"look{'' if k != 1 else 's'} dangerous"
            ),
            (
                "Registered and set up like a real website or mail server. "
                "Start with the top rows of the table."
            ),
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
    counts = {lvl: sum(1 for r in registered if r.risk_level == lvl) for lvl in _LEVELS_DESC}
    total = max(len(registered), 1)
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


def _verdict_card(report: ScanReport) -> Panel:
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
    """Builds a partial results table for the live scanning view."""
    rows = sorted(hits, key=lambda r: r.risk_score, reverse=True)
    if limit <= 0 or len(rows) <= limit:
        return _results_table(domain, rows)
    table = _results_table(domain, rows[:limit])
    table.caption = f"+{len(rows) - limit} more · full table when the scan ends"
    return table


def render_table(report: ScanReport, console: Console, show_safe: bool = False) -> None:
    """Renders scan results as a stylized terminal table."""
    console.print()
    console.print(_verdict_card(report))

    rows = report.results if show_safe else report.registered

    if not rows:
        console.print()
        return

    console.print()
    console.print(_results_table(report.target, rows))

    if any(r.is_likely_defensive for r in rows):
        console.print(
            f"[warn]{GLYPH_DEFENSIVE}[/warn] [muted]= likely defensive: redirects to your own "
            "site, probably registered by you[/muted]"
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
    "_headline",
    "_http_cell",
    "_redirect_host",
    "_results_table",
    "_risk_bar",
    "_signals",
    "_verdict_banner",
    "_verdict_card",
    "_why",
    "build_live_table",
    "render_aggregate_summary",
    "render_table",
]
