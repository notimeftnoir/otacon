"""CLI generate subcommand implementation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from ...permutations.generator import generate as run_generate
from ...utils.validate import is_valid_domain, normalize_domain, safe_cli_path
from ..state import _state
from .scan import _load_exclusions


def execute_generate(
    ctx: typer.Context,
    console: Console,
    domain: str,
    limit: int,
    output: Path | None,
    exclude: str | None,
    exclude_file: Path | None,
) -> None:
    """Generates and prints domain variants without network checks."""
    quiet = _state(ctx).quiet
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        console.print("[danger]Error: invalid domain format.[/danger]")
        raise typer.Exit(1)
    exclusions = _load_exclusions(exclude, exclude_file)
    perms = run_generate(domain, exclude=exclusions)

    console.print(
        f"[field]Generated[/field] [value]{len(perms)}[/value] "
        f"[field]variants for[/field] [value]{escape(domain)}[/value]\n"
    )

    shown = perms[:limit] if limit > 0 else perms
    for p in shown:
        console.print(
            f"  [value]{escape(p.domain):<40}[/value]"
            f" [muted]{p.kind.value:<12} {escape(p.note)}[/muted]"
        )

    if limit and len(perms) > limit:
        console.print(f"\n[muted]... and {len(perms) - limit} more (use --limit 0)[/muted]")

    if output:
        target_path = safe_cli_path(str(output))
        if not target_path:
            console.print(f"[danger]Error: unsafe path: {escape(str(output))}[/danger]")
        else:
            try:
                dest = Path(target_path)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text("\n".join(p.domain for p in perms) + "\n", encoding="utf-8")
                console.print(f"[ok]→ Wordlist saved:[/ok] [url]{escape(target_path)}[/url]")
            except OSError as exc:
                console.print(f"[danger]Error saving wordlist: {escape(str(exc))}[/danger]")

    if quiet and not output:
        sys.stdout.write(json.dumps([p.domain for p in perms]) + "\n")


__all__ = ["execute_generate"]
