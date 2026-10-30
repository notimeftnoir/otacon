"""Diff engine for comparing Otacon scan reports over time."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .core.models import DomainResult, ScanOptions, ScanReport
from .core.types import RiskLevel


class DomainStatus(str, Enum):
    NEW_THREAT = "new_threat"
    NEW_SAFE = "new_safe"
    DROPPED = "dropped"
    MODIFIED = "modified"


class DomainDiff(BaseModel):
    """Changes observed on a single domain between scans."""

    domain: str
    status: str = "new_threat"
    risk_level: RiskLevel = RiskLevel.SAFE
    risk_score: int = 0
    changes: list[str] = Field(default_factory=list)


class ReportDiff(BaseModel):
    """Aggregate diff between an earlier and a later scan report."""

    target: str = ""
    old_date: datetime | None = None
    new_date: datetime | None = None
    new_domains: list[DomainDiff] = Field(default_factory=list)
    dropped_domains: list[DomainDiff] = Field(default_factory=list)
    modified_domains: list[DomainDiff] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)
    """What these two scans did not both check, and so cannot be compared on."""

    @property
    def has_changes(self) -> bool:
        """True if any additions, drops, or modifications were observed."""
        return bool(self.new_domains or self.dropped_domains or self.modified_domains)

    @property
    def has_critical_threat(self) -> bool:
        """True if any new high/critical threat was introduced."""
        return any(d.risk_level.rank >= RiskLevel.HIGH.rank for d in self.new_domains) or any(
            d.risk_level.rank >= RiskLevel.HIGH.rank for d in self.modified_domains
        )


ScanDiff = ReportDiff


def _shared_options(old: ScanReport, new: ScanReport) -> ScanOptions:
    """What both scans actually looked at.

    A signal only one of them probed cannot be compared: the field is empty in
    the other report because nothing asked, not because the answer was no.
    """
    a, b = old.options, new.options
    return ScanOptions(
        http=a.http and b.http,
        whois=a.whois and b.whois,
        dnsbl=a.dnsbl and b.dnsbl,
        ct=a.ct and b.ct,
    )


def _option_caveats(old: ScanReport, new: ScanReport) -> list[str]:
    """Plain-language notes on what these two scans cannot be compared on."""
    a, b = old.options, new.options
    notes = []
    for flag, what in (
        ("http", "websites, certificates, favicons and login forms"),
        ("whois", "registration dates"),
        ("dnsbl", "reputation lists"),
        ("ct", "Certificate Transparency discovery"),
    ):
        if getattr(a, flag) != getattr(b, flag):
            ran, skipped = ("earlier", "later") if getattr(a, flag) else ("later", "earlier")
            notes.append(f"only the {ran} scan checked {what}, so the {skipped} one cannot differ")
    return notes


def _compare_results(
    old: DomainResult, new: DomainResult, shared: ScanOptions | None = None
) -> list[str]:
    """Generates human-readable descriptions of changes between two results.

    *shared* is what both scans probed; anything outside it is left alone.
    Without it a full scan compared against a ``--no-http`` one reported every
    live site as having lost its certificate and every listed domain as having
    just been blacklisted — a nightly cron job's worth of false alarms.
    """
    opts = shared if shared is not None else ScanOptions()
    changes: list[str] = []
    # Scores are a function of every signal, so they are only comparable when
    # both scans gathered the same ones.
    if old.risk_score != new.risk_score and opts == ScanOptions():
        changes.append(f"Score shifted {old.risk_score} → {new.risk_score}")

    # DNS and MX are never gated by a flag: always comparable.
    if not old.has_mx and new.has_mx:
        mx_desc = f": {', '.join(new.mx_records)}" if new.mx_records else ""
        changes.append(f"Mail server added{mx_desc}")
    elif old.has_mx and not new.has_mx:
        changes.append("Mail server removed")

    if set(old.ip_addresses) != set(new.ip_addresses):
        changes.append(f"IP changed: {', '.join(old.ip_addresses)} → {', '.join(new.ip_addresses)}")

    if opts.http:
        if not old.has_ssl and new.has_ssl:
            changes.append(f"SSL certificate added: {new.ssl_issuer or 'unknown'}")

        if not old.favicon_matches_target and new.favicon_matches_target:
            changes.append("Favicon now matches target brand")

        if not old.has_login_form and new.has_login_form:
            changes.append("Credential login form detected")

    if opts.dnsbl and not old.dnsbl_listed and new.dnsbl_listed:
        changes.append(f"Blacklisted on DNSBL ({new.dnsbl_source})")

    return changes


def compute_diff(old: ScanReport, new: ScanReport) -> ReportDiff:
    """Computes differences between *old* and *new* scan reports."""
    old_by_domain = {r.domain: r for r in old.results}
    new_by_domain = {r.domain: r for r in new.results}

    shared = _shared_options(old, new)
    diff = ReportDiff(
        target=new.target or old.target,
        old_date=old.started_at,
        new_date=new.started_at,
        caveats=_option_caveats(old, new),
    )

    for domain, res in new_by_domain.items():
        if domain not in old_by_domain:
            status = (
                "new_threat"
                if res.risk_level.rank >= RiskLevel.LOW.rank or res.is_registered
                else "new_safe"
            )
            diff.new_domains.append(
                DomainDiff(
                    domain=domain,
                    status=status,
                    risk_level=res.risk_level,
                    risk_score=res.risk_score,
                )
            )

    for domain, res in old_by_domain.items():
        if domain not in new_by_domain:
            diff.dropped_domains.append(
                DomainDiff(
                    domain=domain,
                    status="dropped",
                    risk_level=res.risk_level,
                    risk_score=res.risk_score,
                )
            )

    for domain, new_res in new_by_domain.items():
        if domain in old_by_domain:
            old_res = old_by_domain[domain]
            changes = _compare_results(old_res, new_res, shared)
            if changes:
                diff.modified_domains.append(
                    DomainDiff(
                        domain=domain,
                        status="modified",
                        risk_level=new_res.risk_level,
                        risk_score=new_res.risk_score,
                        changes=changes,
                    )
                )

    return diff


def render_diff(diff: ReportDiff, console: Console) -> None:
    """Renders the diff comparison report to the terminal using Rich."""
    head = Text()
    head.append("OTACON DIFF", style="bold brand")
    head.append(f" · Target: {diff.target}\n", style="brand")
    if diff.old_date:
        head.append(
            f"Earlier scan: {diff.old_date.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            style="muted",
        )
    if diff.new_date:
        head.append(
            f"Later scan: {diff.new_date.strftime('%Y-%m-%d %H:%M:%S UTC')}\n",
            style="muted",
        )

    console.print(Panel(head, border_style="brand"))

    for note in diff.caveats:
        console.print(f"[warn]⚠  These scans are not directly comparable: {note}.[/warn]")
    if diff.caveats:
        console.print()

    if not diff.has_changes:
        console.print("[ok]✓ No changes detected between scan reports.[/ok]\n")
        return

    table = Table(title="Observed Domain Changes", border_style="muted")
    table.add_column("Domain", style="bold")
    table.add_column("Status")
    table.add_column("Risk")
    table.add_column("Changes / Details")

    for d in diff.new_domains:
        status_style = "danger" if d.status == "new_threat" else "ok"
        table.add_row(
            Text(d.domain, style="value"),
            Text(d.status, style=status_style),
            Text(f"{d.risk_level.value} ({d.risk_score})", style=d.risk_level.style),
            Text("Newly registered lookalike variant"),
        )

    for d in diff.modified_domains:
        table.add_row(
            Text(d.domain, style="value"),
            Text("modified", style="warn"),
            Text(f"{d.risk_level.value} ({d.risk_score})", style=d.risk_level.style),
            Text(" · ".join(d.changes)),
        )

    for d in diff.dropped_domains:
        table.add_row(
            Text(d.domain, style="value"),
            Text("dropped", style="muted"),
            Text(f"{d.risk_level.value} ({d.risk_score})", style=d.risk_level.style),
            Text("No longer detected in scan"),
        )

    console.print(table)
    console.print()


_diff_summary = render_diff
_render_diff_table = render_diff


def _load_report(path: Path) -> ScanReport:
    """Loads and validates a ScanReport from a JSON file."""
    return ScanReport.model_validate_json(path.read_text(encoding="utf-8"))


__all__ = [
    "DomainDiff",
    "DomainStatus",
    "ReportDiff",
    "ScanDiff",
    "_compare_results",
    "_diff_summary",
    "_load_report",
    "_option_caveats",
    "_render_diff_table",
    "_shared_options",
    "compute_diff",
    "render_diff",
]
