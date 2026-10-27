"""Threat intelligence dossier and incident evidence visualizer."""

from __future__ import annotations

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.models import DomainResult
from ..net.whois import format_age


def _evidence(r: DomainResult) -> list[tuple[str, str, str]]:
    """Constructs (label, fact, meaning) structured evidence rows."""
    rows: list[tuple[str, str, str]] = []
    if r.resolves:
        rows.append(("Online", ", ".join(r.ip_addresses[:3]), "points to a live server"))
    if r.has_mx:
        rows.append(
            ("Mail", ", ".join(r.mx_records[:2]), "can send email that looks like it is from you")
        )
    if r.redirects_to:
        meaning = (
            "sends visitors to your own site, likely yours"
            if r.is_likely_defensive
            else "sends visitors somewhere else"
        )
        rows.append(("Redirect", r.redirects_to, meaning))
    elif r.http_status is not None:
        title = f'"{r.page_title}"' if r.page_title else f"HTTP {r.http_status}"
        meaning = "a page is up"
        if r.title_similarity is not None and r.title_similarity >= 0.8:
            meaning = "its page title copies yours"
        rows.append(("Website", title, meaning))
    if r.has_ssl:
        age = f", {r.ssl_cert_age_days} days old" if r.ssl_cert_age_days is not None else ""
        rows.append(
            ("Certificate", f"{r.ssl_issuer or 'unknown issuer'}{age}", "browsers show a padlock")
        )
    if r.age_days is not None:
        rows.append(("Registered", format_age(r.age_days) + " ago", "domain age from WHOIS/RDAP"))
    if r.has_mx:
        spoof_info = (
            f"DMARC: {r.dmarc_policy or 'none'} (spoofable)"
            if r.is_mail_spoofable
            else f"DMARC: {r.dmarc_policy or 'enforced'}"
        )
        meaning = (
            "attacker can spoof email as this domain"
            if r.is_mail_spoofable
            else "mail exchanger configured"
        )
        rows.append(("Mail Security", spoof_info, meaning))
    if r.favicon_matches_target:
        rows.append(
            ("Favicon", f"matches target (hash: {r.favicon_hash})", "cloned brand visual identity")
        )
    if r.has_login_form:
        rows.append(("Login Form", "password input detected", "credential harvesting form on site"))
    if r.dnsbl_listed:
        rows.append(
            ("Reputation", r.dnsbl_source or "Listed", "known malicious / phishing threat IOC")
        )
    if r.is_sinkhole:
        rows.append(
            ("Sinkhole", "law enforcement / security sinkhole", "threat intercepted by authorities")
        )
    elif r.is_parked:
        rows.append(("Parked", "placeholder page", "not in use yet, keep an eye on it"))
    return rows


def _dossier(r: DomainResult) -> Panel:
    """Renders a comprehensive threat card for a domain result."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="field", no_wrap=True)
    grid.add_column(style="value", overflow="fold")
    grid.add_column(style="muted")
    for label, fact, meaning in _evidence(r):
        grid.add_row(label, Text(fact), meaning)

    head = Text()
    head.append(f"{r.risk_level.icon} {r.risk_level.value.upper()} ", style=r.risk_level.style)
    head.append(f"{r.risk_score}/100", style="value")
    head.append(f"   {r.kind.value}", style="brand.dim")
    if r.note:
        head.append(f" · {r.note}", style="muted")
    parts: list[Text | Table] = [head, Text()]
    if grid.row_count:
        parts.append(grid)
    else:
        parts.append(Text("No network signals: registered, but nothing is running.", "muted"))
    return Panel(
        Group(*parts),
        title=Text(f" {r.domain} ", style="bold white"),
        title_align="left",
        border_style=r.risk_level.style,
        box=box.SQUARE,
        padding=(1, 2),
    )


__all__ = ["_dossier", "_evidence"]
