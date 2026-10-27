"""CLI tui subcommand implementation."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from ..._asyncutils import run_async
from ...core.models import ScanReport
from ...engine.scanner import run_scan
from ...utils.validate import is_valid_domain, normalize_domain


def execute_tui(
    console: Console,
    domain: str | None,
    report_file: Path | None,
    concurrency: int,
    check_http: bool,
    check_whois: bool,
    check_dnsbl: bool,
    check_ct: bool,
) -> None:
    """Scans *domain* (or loads *report_file*) and opens the triage console on it."""
    if (domain is None) == (report_file is None):
        console.print("[danger]Pass either a domain to scan or --from <report.json>.[/danger]")
        raise typer.Exit(1)

    if report_file is not None:
        # Matches execute_diff: an input path typed by the operator is read as given.
        if not report_file.exists() or not report_file.is_file():
            console.print(f"[danger]Error: file not found: {escape(str(report_file))}[/danger]")
            raise typer.Exit(1)
        try:
            report = ScanReport.model_validate_json(report_file.read_text(encoding="utf-8"))
        except Exception as exc:
            console.print(f"[danger]Error parsing JSON report: {escape(str(exc))}[/danger]")
            raise typer.Exit(1) from exc
    else:
        assert domain is not None  # narrowed by the mutual-exclusion check above
        target = normalize_domain(domain)
        if not is_valid_domain(target):
            console.print(f"[danger]Error: invalid domain: {escape(domain)}[/danger]")
            raise typer.Exit(1)
        report = run_async(
            run_scan(
                target=target,
                concurrency=concurrency,
                check_http=check_http,
                console=console,
                check_whois=check_whois,
                check_dnsbl=check_dnsbl,
                check_ct=check_ct,
            )
        )

    if not report.results:
        console.print(f"[warn]Nothing to triage for {escape(report.target)}.[/warn]")
        raise typer.Exit(0)

    # Imported here so the Textual dependency is only loaded for this command;
    # `otacon scan` in a CI container never pays for it.
    from ...tui import run_tui

    run_tui(report)


__all__ = ["execute_tui"]
