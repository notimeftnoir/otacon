from __future__ import annotations

import asyncio
import sys
from enum import Enum
from pathlib import Path

# Windows ProactorEventLoop raises ConnectionResetError (WinError 10054) on
# normal HTTP connection teardowns. SelectorEventLoop doesn't have this issue.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

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
from .theme import BANNER, OTACON_THEME, RiskLevel


class _Threshold(str, Enum):
    """Valid threshold levels for --fail-on (excludes 'safe')."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

app = typer.Typer(
    name="otacon",
    help="Domain impersonation detector (typosquatting / impersonation).",
    add_completion=False,
)

console = Console(theme=OTACON_THEME)


def _banner() -> None:
    console.print(BANNER)


def _version_callback(value: bool) -> None:
    if value:
        from . import __version__
        console.print(f"[brand]otacon[/brand] [value]{__version__}[/value]")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def _main(
    ctx: typer.Context,
    version: bool = typer.Option(  # noqa: B008
        False, "--version", "-V",
        callback=_version_callback, is_eager=True,
        help="Print version and exit.",
    ),
) -> None:
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
    html_out: Path = typer.Option(
        None, "--html", help="Write a self-contained HTML report to a file."
    ),
    no_http: bool = typer.Option(
        False, "--no-http", help="Skip HTTP/SSL probing (faster, fewer signals)."
    ),
    concurrency: int = typer.Option(
        50, "--concurrency", "-c", help="Number of concurrent checks.", min=1
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
    fail_on: _Threshold = typer.Option(
        None, "--fail-on",
        help="Exit 2 if any registered result meets or exceeds this risk level."
             " Choices: low medium high critical.",
    ),
) -> None:
    """Scans domain variants and detects registered fakes."""
    domain = domain.strip().lower().removeprefix("www.")
    if not domain:
        console.print("[danger]Error: domain cannot be empty.[/danger]")
        raise typer.Exit(1)

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
        try:
            json_out.write_text(reporters.to_json(report), encoding="utf-8")
            console.print(f"[ok]\u2192 JSON saved:[/ok] [url]{json_out}[/url]")
        except OSError as exc:
            console.print(f"[danger]Error saving JSON: {exc}[/danger]")

    if md_out:
        try:
            md_out.write_text(reporters.to_markdown(report), encoding="utf-8")
            console.print(f"[ok]\u2192 Markdown saved:[/ok] [url]{md_out}[/url]")
        except OSError as exc:
            console.print(f"[danger]Error saving Markdown: {exc}[/danger]")

    if html_out:
        try:
            from .html_report import to_html
            html_out.write_text(to_html(report), encoding="utf-8")
            console.print(f"[ok]\u2192 HTML saved:[/ok] [url]{html_out}[/url]")
        except OSError as exc:
            console.print(f"[danger]Error saving HTML: {exc}[/danger]")

    if fail_on is not None:
        threshold = RiskLevel(fail_on.value)
        if any(r.risk_level.rank >= threshold.rank for r in report.registered):
            raise typer.Exit(2)


@app.command()
def watch(
    domain: str = typer.Argument(..., help="Domain to monitor for impersonation."),
    interval: str = typer.Option(
        None, "--interval",
        help="Re-run every interval (e.g. 24h, 30m, 60s). Omit for a single run.",
    ),
    notify_url: str = typer.Option(
        None, "--notify",
        help="Webhook URL. POST JSON diff when NEW/CHANGED domains reach high/critical.",
    ),
    json_out: Path = typer.Option(None, "--json", help="Write diff JSON to this file."),
    no_http: bool = typer.Option(False, "--no-http", help="Skip HTTP/SSL probing."),
    concurrency: int = typer.Option(50, "--concurrency", "-c", min=1),
    exclude: str = typer.Option(None, "--exclude", "-x"),
    exclude_file: Path = typer.Option(None, "--exclude-file"),
) -> None:
    """Scans domain variants and diffs against a saved baseline.

    Shows only NEW / CHANGED / GONE since the last run.
    """
    domain = domain.strip().lower().removeprefix("www.")
    if not domain:
        console.print("[danger]Error: domain cannot be empty.[/danger]")
        raise typer.Exit(1)

    interval_secs: int | None = None
    if interval:
        from .watch import parse_interval as _parse_interval
        try:
            interval_secs = _parse_interval(interval)
        except ValueError as exc:
            console.print(f"[danger]Error: {exc}[/danger]")
            raise typer.Exit(1) from exc

    exclusions = _load_exclusions(exclude, exclude_file)

    async def _loop() -> None:
        from . import watch as _watch
        from .state import load_baseline, save_baseline

        while True:
            report = await _run_scan(
                domain, concurrency, check_http=not no_http, exclude=exclusions
            )
            baseline = load_baseline(domain)
            diff = _watch.compute_diff(domain, report.results, baseline)

            _watch.render_diff(diff, console)
            save_baseline(domain, report.results)

            if json_out:
                try:
                    json_out.write_text(diff.model_dump_json(indent=2), encoding="utf-8")
                    console.print(f"[ok]→ Diff JSON saved:[/ok] [url]{json_out}[/url]")
                except OSError as exc:
                    console.print(f"[danger]Error saving diff: {exc}[/danger]")

            if notify_url and _watch.has_high_priority_changes(diff):
                await _watch.notify(notify_url, diff)

            if interval_secs is None:
                break

            console.print(f"[muted]Next scan in {interval}…[/muted]")
            await asyncio.sleep(interval_secs)

    try:
        asyncio.run(_loop())
    except KeyboardInterrupt:
        console.print("\n[muted]Watch stopped.[/muted]")


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


if __name__ == "__main__":
    app()
