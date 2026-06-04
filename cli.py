from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from . import permutations, reporters, scoring
from .models import ScanReport
from .resolver import Resolver
from .theme import BANNER, OTACON_THEME

app = typer.Typer(
    name="otacon",
    help="Domain impersonation detector (typosquatting / impersonation).",
    add_completion=False,
)

console = Console(theme=OTACON_THEME)


def _banner() -> None:
    console.print(BANNER)


@app.callback(invoke_without_command=True)
def _main(ctx: typer.Context) -> None:
    """Shows the banner before any command; enters interactive mode when run bare."""
    _banner()
    if ctx.invoked_subcommand is None:
        from .interactive import run as _interactive_run
        _interactive_run(console)
        raise typer.Exit()


def _load_exclusions(raw: str | None, file: Path | None) -> set[str]:
    """Builds the whitelist from the CLI option (commas) and/or a file.

    Both sources can be combined. In a file, blank lines and lines starting
    with '#' (comments) are ignored.
    """
    out: set[str] = set()
    if raw:
        out.update(d.strip().lower() for d in raw.split(",") if d.strip())
    if file:
        try:
            content = file.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise typer.BadParameter(f"exclude-file not found: {file}") from exc
        except OSError as exc:
            raise typer.BadParameter(f"cannot read exclude-file: {file}") from exc

        for line in content.splitlines():
            entry = line.strip().lower()
            if entry and not entry.startswith("#"):
                out.add(entry)
    return out


async def _run_scan(
    target: str,
    concurrency: int,
    check_http: bool,
    exclude: set[str] | None = None,
) -> ScanReport:
    """Runs a full scan with a progress bar."""
    perms = permutations.generate(target, exclude=exclude)
    report = ScanReport(target=target, total_permutations=len(perms))

    if not perms:
        return report

    with Progress(
        SpinnerColumn(style="brand"),
        TextColumn("[field]{task.description}"),
        BarColumn(complete_style="brand", finished_style="ok"),
        TextColumn("[muted]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Checking variants", total=len(perms))

        async with Resolver(concurrency=concurrency, check_http=check_http) as resolver:
            # Checked one by one to update the progress bar as results arrive.
            coros = [resolver.check_one(p) for p in perms]
            for coro in asyncio.as_completed(coros):
                result = await coro
                report.results.append(scoring.score(result, target))
                progress.advance(task)

    return report


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Domain to protect, e.g. example.com"),
    json_out: Path = typer.Option(
        None, "--json", help="Write the full JSON report to a file."
    ),
    md_out: Path = typer.Option(
        None, "--markdown", "--md", help="Write the Markdown report to a file."
    ),
    no_http: bool = typer.Option(
        False, "--no-http", help="Skip HTTP/SSL probing (faster, fewer signals)."
    ),
    concurrency: int = typer.Option(
        50, "--concurrency", "-c", help="Number of concurrent checks."
    ),
    show_all: bool = typer.Option(
        False, "--all", help="Show unregistered variants too."
    ),
    exclude: str = typer.Option(
        None, "--exclude", "-x",
        help="Whitelist of domains to skip (comma-separated), e.g. legit aliases."
    ),
    exclude_file: Path = typer.Option(
        None, "--exclude-file",
        help="File with a whitelist (one domain per line, '#' = comment)."
    ),
) -> None:
    """Scans domain variants and detects registered fakes."""
    exclusions = _load_exclusions(exclude, exclude_file)
    console.print(f"[field]Target:[/field] [value]{escape(domain)}[/value]")
    console.print(
        f"[muted]Mode: {'DNS only' if no_http else 'DNS + HTTP/SSL'} \u00b7 "
        f"concurrency: {concurrency}"
        + (f" \u00b7 whitelist: {len(exclusions)}" if exclusions else "")
        + "[/muted]"
    )

    report = asyncio.run(
        _run_scan(domain, concurrency, check_http=not no_http, exclude=exclusions)
    )

    reporters.render_table(report, console, show_safe=show_all)

    if json_out:
        json_out.write_text(reporters.to_json(report), encoding="utf-8")
        console.print(f"[ok]\u2192 JSON saved:[/ok] [url]{json_out}[/url]")

    if md_out:
        md_out.write_text(reporters.to_markdown(report), encoding="utf-8")
        console.print(f"[ok]\u2192 Markdown saved:[/ok] [url]{md_out}[/url]")


@app.command()
def generate(
    domain: str = typer.Argument(..., help="Domain to permute."),
    limit: int = typer.Option(0, "--limit", "-n", help="Display limit (0 = all)."),
    exclude: str = typer.Option(
        None, "--exclude", "-x", help="Whitelist of domains to skip (comma-separated)."
    ),
    exclude_file: Path = typer.Option(
        None, "--exclude-file", help="File with a whitelist (one domain per line)."
    ),
) -> None:
    """Generates and prints variants WITHOUT network checks (offline, fast)."""
    exclusions = _load_exclusions(exclude, exclude_file)
    perms = permutations.generate(domain, exclude=exclusions)

    console.print(
        f"[field]Generated[/field] [value]{len(perms)}[/value] "
        f"[field]variants for[/field] [value]{domain}[/value]\n"
    )

    shown = perms[:limit] if limit > 0 else perms
    for p in shown:
        console.print(
            f"  [value]{p.domain:<40}[/value] [muted]{p.kind.value:<12} {p.note}[/muted]"
        )

    if limit and len(perms) > limit:
        console.print(f"\n[muted]... and {len(perms) - limit} more (use --limit 0)[/muted]")


if __name__ == "__main__":
    app()
