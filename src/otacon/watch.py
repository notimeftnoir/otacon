"""Watch mode — continuous monitoring with baseline diff.

Compares a fresh scan against a saved baseline and reports only what changed:
NEW (appeared), CHANGED (risk score/level shifted), GONE (no longer registered).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

import httpx
from pydantic import BaseModel, Field
from rich.console import Console
from rich.text import Text

from .models import DomainResult
from .theme import RiskLevel

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class DomainChange(BaseModel):
    """A domain whose risk profile changed since the last baseline."""

    domain: str
    old_score: int
    old_level: RiskLevel
    new_result: DomainResult


class WatchDiff(BaseModel):
    """Complete diff between a fresh scan and the saved baseline."""

    target: str
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    new_domains: list[DomainResult] = Field(default_factory=list)
    changed_domains: list[DomainChange] = Field(default_factory=list)
    gone_domains: list[str] = Field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_domains or self.changed_domains or self.gone_domains)


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------


def compute_diff(
    target: str,
    current: list[DomainResult],
    baseline: dict[str, dict] | None,
) -> WatchDiff:
    """Classifies *current* results as NEW / CHANGED / GONE vs *baseline*.

    ``baseline=None`` and ``baseline={}`` both mean "no prior data" — all
    registered domains are NEW.
    """
    diff = WatchDiff(target=target)
    current_registered = {r.domain: r for r in current if r.is_registered}
    baseline = baseline or {}
    baseline_domains = set(baseline.keys())

    for domain, result in current_registered.items():
        if domain not in baseline_domains:
            diff.new_domains.append(result)
        else:
            old = baseline[domain]
            old_score = int(old.get("risk_score", 0))
            try:
                old_level = RiskLevel(old.get("risk_level", "safe"))
            except ValueError:
                old_level = RiskLevel.SAFE
            if result.risk_score != old_score or result.risk_level != old_level:
                diff.changed_domains.append(
                    DomainChange(
                        domain=domain,
                        old_score=old_score,
                        old_level=old_level,
                        new_result=result,
                    )
                )

    for domain in baseline_domains:
        if domain not in current_registered:
            diff.gone_domains.append(domain)

    return diff


# ---------------------------------------------------------------------------
# Interval parsing
# ---------------------------------------------------------------------------

_INTERVAL_RE = re.compile(r"^(\d+)(h|m|s)$")
_MULTIPLIERS = {"h": 3600, "m": 60, "s": 1}


def parse_interval(s: str) -> int:
    """Parses ``'24h'``, ``'30m'``, ``'60s'`` → seconds. Raises ``ValueError`` on bad input."""
    m = _INTERVAL_RE.match(s.strip())
    if not m:
        raise ValueError(
            f"Invalid interval {s!r}. Use a number followed by h/m/s (e.g. 24h, 30m, 60s)."
        )
    return int(m.group(1)) * _MULTIPLIERS[m.group(2)]


# ---------------------------------------------------------------------------
# Console rendering
# ---------------------------------------------------------------------------


def render_diff(diff: WatchDiff, console: Console) -> None:
    """Prints a human-readable diff to *console*."""
    if not diff.has_changes:
        console.print("\n[ok]✓ No changes since last scan.[/ok]\n")
        return

    console.print()

    if diff.new_domains:
        by_score = sorted(diff.new_domains, key=lambda r: r.risk_score, reverse=True)
        console.print(f"[brand]NEW[/brand] ({len(diff.new_domains)})")
        for r in by_score:
            _print_row(console, r.domain, None, None, r.risk_score, r.risk_level)

    if diff.changed_domains:
        by_score = sorted(diff.changed_domains, key=lambda c: c.new_result.risk_score, reverse=True)
        console.print(f"\n[warn]CHANGED[/warn] ({len(diff.changed_domains)})")
        for c in by_score:
            _print_row(
                console,
                c.domain,
                c.old_score,
                c.old_level,
                c.new_result.risk_score,
                c.new_result.risk_level,
            )

    if diff.gone_domains:
        console.print(f"\n[muted]GONE[/muted] ({len(diff.gone_domains)})")
        for domain in sorted(diff.gone_domains):
            console.print(f"  [muted]- {domain}[/muted]")

    console.print()


def _print_row(
    console: Console,
    domain: str,
    old_score: int | None,
    old_level: RiskLevel | None,
    new_score: int,
    new_level: RiskLevel,
) -> None:
    t = Text()
    t.append(f"  {domain}", style="value")
    if old_score is not None and old_level is not None:
        t.append(f"  {old_level.value}({old_score})", style=old_level.style)
        t.append(" → ", style="muted")
    else:
        t.append("  ")
    t.append(f"{new_level.value}({new_score})", style=new_level.style)
    console.print(t)


# ---------------------------------------------------------------------------
# Webhook notification
# ---------------------------------------------------------------------------


def has_high_priority_changes(diff: WatchDiff) -> bool:
    """Returns True when any NEW or CHANGED domain is high or critical risk."""
    for r in diff.new_domains:
        if r.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return True
    for c in diff.changed_domains:
        if c.new_result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return True
    return False


async def notify(url: str, diff: WatchDiff) -> None:
    """POSTs *diff* as JSON to *url*. Failures are swallowed — never abort the scan."""
    if not url.startswith(("http://", "https://")):
        return
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                url,
                content=diff.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
    except Exception:
        pass
