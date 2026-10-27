"""Markdown report generation for tickets, GitHub issues, and documentation."""

from __future__ import annotations

from ..core.models import ScanReport
from ..core.types import RiskLevel
from ..scoring.engine import count_fresh, get_age_fresh_days
from .console import _signals


def _verdict_banner_md(report: ScanReport) -> str:
    """Plain-text verdict summary line for markdown documents."""
    registered = report.registered
    if not registered:
        return f"✓ **clean** — {report.total_permutations} permutations checked, none registered"

    threats = report.threats
    crit_count = sum(1 for r in threats if r.risk_level == RiskLevel.CRITICAL)
    mx_count = sum(1 for r in registered if r.has_mx)
    fresh_days = get_age_fresh_days()
    fresh_count = count_fresh(registered)
    icon = "⚠" if crit_count else "●"
    return (
        f"{icon} **{len(registered)} registered** · "
        f"crit: {crit_count} · mx: {mx_count} · fresh <{fresh_days}d: {fresh_count}"
    )


def to_markdown(report: ScanReport) -> str:
    """Generates a Markdown threat report ready to paste into documentation or tickets."""
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


__all__ = ["_verdict_banner_md", "to_markdown"]
