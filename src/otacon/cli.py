from __future__ import annotations

import asyncio
import io
import logging
import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from . import permutations, reporters, scoring
from ._asyncutils import run_async
from ._validate import is_safe_webhook_url, is_valid_domain, safe_relative_path
from .models import DomainResult, ScanReport
from .resolver import Resolver
from .theme import BANNER, OTACON_THEME, RiskLevel

QUIET_MODE = False


def _ensure_unicode_output() -> None:
    """Keeps the Unicode UI (⬢, █, ✓, →) from crashing non-UTF-8 consoles.

    Windows consoles often default to a legacy codepage (cp1250/cp852) whose
    charmap codec raises UnicodeEncodeError on the banner glyphs. Re-encode to
    UTF-8 there; elsewhere just make sure an exotic locale degrades to '?'
    instead of a traceback.
    """
    for stream in (sys.stdout, sys.stderr):
        if not isinstance(stream, io.TextIOWrapper):
            continue
        try:
            if (stream.encoding or "").lower().replace("-", "") != "utf8":
                if sys.platform == "win32":
                    stream.reconfigure(encoding="utf-8", errors="replace")
                else:
                    stream.reconfigure(errors="replace")
        except (OSError, ValueError):
            pass


_ensure_unicode_output()


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


def _configure_logging(debug: bool) -> None:
    """Wires the ``otacon`` logger to a Rich handler. Off unless ``--debug``.

    Without this, the library's many graceful-degradation paths (WHOIS misses,
    DNS errors, dropped webhooks) are invisible — this makes them surface at
    DEBUG on demand without ever leaking into normal output.
    """
    from rich.logging import RichHandler

    logger = logging.getLogger("otacon")
    logger.handlers.clear()
    if not debug:
        logger.addHandler(logging.NullHandler())
        return
    handler = RichHandler(console=console, show_path=False, rich_tracebacks=True)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)


@app.callback(invoke_without_command=True)
def _main(
    ctx: typer.Context,
    version: bool = typer.Option(  # noqa: B008
        False, "--version", "-V",
        callback=_version_callback, is_eager=True,
        help="Print version and exit.",
    ),
    debug: bool = typer.Option(
        False, "--debug",
        help="Log graceful-degradation events (DNS/WHOIS/HTTP/webhook failures) to stderr.",
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Disable UI, banner, and progress. Outputs JSON to stdout.",
    ),
) -> None:
    """Shows the banner before any command; enters interactive mode when run bare."""
    global QUIET_MODE
    QUIET_MODE = quiet
    if quiet:
        console.quiet = True

    _configure_logging(debug)
    if not quiet:
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
    """Runs a full scan; streams registered hits into a live table as they arrive."""
    perms = permutations.generate(target, exclude=exclude)
    report = ScanReport(target=target, total_permutations=len(perms))

    if not perms:
        return report

    hits: list[DomainResult] = []

    if QUIET_MODE:
        async with Resolver(concurrency=concurrency, check_http=check_http) as resolver:
            coros = [resolver.check_one(p) for p in perms]
            for coro in asyncio.as_completed(coros):
                result = await coro
                scored = scoring.score(result, target)
                report.results.append(scored)
                if scored.is_registered:
                    hits.append(scored)
            report.dns_hijack_detected = resolver.dns_hijack_detected
    else:
        progress = Progress(
            SpinnerColumn(style="brand"),
            TextColumn("[field]{task.description}"),
            BarColumn(complete_style="brand", finished_style="ok"),
            TextColumn("[muted]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        )
        task = progress.add_task("Checking variants", total=len(perms))

        with Live(progress, console=console, refresh_per_second=4, transient=True) as live:
            async with Resolver(concurrency=concurrency, check_http=check_http) as resolver:
                coros = [resolver.check_one(p) for p in perms]
                for coro in asyncio.as_completed(coros):
                    result = await coro
                    scored = scoring.score(result, target)
                    report.results.append(scored)
                    progress.advance(task)
                    if scored.is_registered:
                        hits.append(scored)
                        live.update(Group(progress, reporters.build_live_table(hits, target)))
                report.dns_hijack_detected = resolver.dns_hijack_detected

    if report.dns_hijack_detected:
        console.print(
            "[warn]⚠  Your DNS resolver answers nonexistent domains (NXDOMAIN hijacking)."
            " Hijacked answers were discarded; consider scanning with a clean resolver"
            " (e.g. 1.1.1.1).[/warn]"
        )
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
    csv_out: Path = typer.Option(
        None, "--csv", help="Write a CSV report to a file."
    ),
    no_http: bool = typer.Option(
        False, "--no-http", help="Skip HTTP/SSL probing (faster, fewer signals)."
    ),
    concurrency: int = typer.Option(
        50, "--concurrency", "-c", help="Number of concurrent checks.", min=1, max=500
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
    if not is_valid_domain(domain):
        console.print("[danger]Error: invalid domain format.[/danger]")
        raise typer.Exit(1)

    exclusions = _load_exclusions(exclude, exclude_file)
    console.print(f"[field]Target:[/field] [value]{escape(domain)}[/value]")
    console.print(
        f"[muted]Mode: {'DNS only' if no_http else 'DNS + HTTP/SSL'} \u00b7 "
        f"concurrency: {concurrency}"
        + (f" \u00b7 whitelist: {len(exclusions)}" if exclusions else "")
        + "[/muted]"
    )

    report = run_async(
        _run_scan(domain, concurrency, check_http=not no_http, exclude=exclusions)
    )

    reporters.render_table(report, console, show_safe=show_all)

    if QUIET_MODE:
        sys.stdout.write(reporters.to_json(report) + "\n")

    def _safe_write(path: Path | None, content: str, label: str) -> None:
        if not path:
            return
        safe_path = safe_relative_path(str(path))
        if not safe_path:
            console.print(f"[danger]Error: refusing to write to unsafe path: {path}[/danger]")
            return
        try:
            Path(safe_path).write_text(content, encoding="utf-8")
            console.print(f"[ok]\u2192 {label} saved:[/ok] [url]{safe_path}[/url]")
        except OSError as exc:
            console.print(f"[danger]Error saving {label}: {exc}[/danger]")

    if json_out:
        _safe_write(json_out, reporters.to_json(report), "JSON")
    if md_out:
        _safe_write(md_out, reporters.to_markdown(report), "Markdown")
    if csv_out:
        _safe_write(csv_out, reporters.to_csv(report), "CSV")
    if html_out:
        from .html_report import to_html
        _safe_write(html_out, to_html(report), "HTML")

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
    concurrency: int = typer.Option(
        50, "--concurrency", "-c", min=1, max=500, help="Max concurrent DNS/HTTP checks."
    ),
    exclude: str = typer.Option(
        None, "--exclude", "-x", help="Domains to skip (comma-separated)."
    ),
    exclude_file: Path = typer.Option(
        None, "--exclude-file", help="File with domains to skip (one per line)."
    ),
) -> None:
    """Scans domain variants and diffs against a saved baseline.

    Shows only NEW / CHANGED / GONE since the last run.
    """
    domain = domain.strip().lower().removeprefix("www.")
    if not is_valid_domain(domain):
        console.print("[danger]Error: invalid domain format.[/danger]")
        raise typer.Exit(1)

    if notify_url and not is_safe_webhook_url(notify_url):
        console.print("[danger]Error: insecure or invalid notify URL.[/danger]")
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
            try:
                save_baseline(domain, report.results)
            except OSError as exc:
                console.print(f"[danger]Warning: could not save baseline: {exc}[/danger]")

            if json_out:
                safe_path = safe_relative_path(str(json_out))
                if not safe_path:
                    console.print(f"[danger]Error: unsafe path: {json_out}[/danger]")
                else:
                    try:
                        Path(safe_path).write_text(diff.model_dump_json(indent=2), encoding="utf-8")
                        console.print(f"[ok]→ Diff JSON saved:[/ok] [url]{safe_path}[/url]")
                    except OSError as exc:
                        console.print(f"[danger]Error saving diff: {exc}[/danger]")

            if QUIET_MODE and diff.has_changes:
                sys.stdout.write(diff.model_dump_json() + "\n")

            if notify_url and _watch.has_high_priority_changes(diff):
                await _watch.notify(notify_url, diff)

            if interval_secs is None:
                break

            console.print(f"[muted]Next scan in {interval}…[/muted]")
            await asyncio.sleep(interval_secs)

    try:
        run_async(_loop())
    except KeyboardInterrupt:
        console.print("\n[muted]Watch stopped.[/muted]")


@app.command()
def generate(
    domain: str = typer.Argument(..., help="Domain to permute."),
    limit: int = typer.Option(0, "--limit", "-n", min=0, help="Display limit (0 = all)."),
    output: Path = typer.Option(
        None, "--output", "-o",
        help="Write variant domains (one per line) to a file — useful as a wordlist.",
    ),
    exclude: str = typer.Option(
        None, "--exclude", "-x", help="Whitelist of domains to skip (comma-separated)."
    ),
    exclude_file: Path = typer.Option(
        None, "--exclude-file", help="File with a whitelist (one domain per line)."
    ),
) -> None:
    """Generates and prints variants WITHOUT network checks (offline, fast)."""
    domain = domain.strip().lower().removeprefix("www.")
    if not is_valid_domain(domain):
        console.print("[danger]Error: invalid domain format.[/danger]")
        raise typer.Exit(1)
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

    if output:
        safe_path = safe_relative_path(str(output))
        if not safe_path:
            console.print(f"[danger]Error: unsafe path: {output}[/danger]")
        else:
            try:
                Path(safe_path).write_text(
                    "\n".join(p.domain for p in perms) + "\n", encoding="utf-8"
                )
                console.print(f"[ok]→ Wordlist saved:[/ok] [url]{safe_path}[/url]")
            except OSError as exc:
                console.print(f"[danger]Error saving wordlist: {exc}[/danger]")

    if QUIET_MODE and not output:
        import json
        sys.stdout.write(json.dumps([p.domain for p in perms]) + "\n")


if __name__ == "__main__":
    app()
