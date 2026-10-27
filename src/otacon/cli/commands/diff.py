"""CLI diff subcommand implementation."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from ...core.models import ScanReport
from ...diff import compute_diff, render_diff
from ...utils.validate import safe_cli_path
from ..state import _state


def execute_diff(
    ctx: typer.Context,
    console: Console,
    file1: Path,
    file2: Path,
    json_out: Path | None,
    fail_on_threats: bool,
) -> None:
    """Compares two Otacon scan reports to detect new registrations and threat shifts."""
    quiet = _state(ctx).quiet

    if not file1.exists() or not file1.is_file():
        console.print(f"[danger]Error: file not found: {escape(str(file1))}[/danger]")
        raise typer.Exit(1)
    if not file2.exists() or not file2.is_file():
        console.print(f"[danger]Error: file not found: {escape(str(file2))}[/danger]")
        raise typer.Exit(1)

    try:
        report1 = ScanReport.model_validate_json(file1.read_text(encoding="utf-8"))
        report2 = ScanReport.model_validate_json(file2.read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[danger]Error parsing JSON reports: {escape(str(exc))}[/danger]")
        raise typer.Exit(1) from exc

    diff_result = compute_diff(report1, report2)

    if quiet:
        if json_out is None:
            sys.stdout.write(diff_result.model_dump_json(indent=2) + "\n")
    else:
        render_diff(diff_result, console)

    if json_out is not None:
        safe_path = safe_cli_path(str(json_out))
        if not safe_path:
            console.print(f"[danger]Error: unsafe output path: {escape(str(json_out))}[/danger]")
            raise typer.Exit(1)
        dest = Path(safe_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(diff_result.model_dump_json(indent=2), encoding="utf-8")
        if not quiet:
            console.print(f"[ok]→ Diff report saved:[/ok] [url]{escape(safe_path)}[/url]\n")

    if fail_on_threats and diff_result.has_critical_threat:
        if not quiet:
            console.print(
                "[danger]CI gate failed: new high or critical threats discovered.[/danger]"
            )
        raise typer.Exit(2)


__all__ = ["execute_diff"]
