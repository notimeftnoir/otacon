"""Typer CLI entry point: ``scan``, ``generate``, plus bare-call interactive mode."""

from __future__ import annotations

import io
import logging
import signal as _signal
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from . import permutations, reporters, scoring
from ._asyncutils import run_async
from ._scanner import run_scan
from ._validate import (
    is_valid_domain,
    normalize_domain,
    parse_domain_list,
    safe_relative_path,
)
from .models import ScanReport
from .theme import BANNER, OTACON_THEME, RiskLevel


@dataclass(frozen=True)
class _CliState:
    """Per-invocation state set by the root callback, read by subcommands.

    Lives on ``typer.Context.obj`` so the CLI has no mutable module globals.
    """

    quiet: bool = False


def _state(ctx: typer.Context) -> _CliState:
    """Returns the active _CliState. Defaults to a fresh frozen instance so
    direct subcommand invocation in tests (bypassing the root callback) is safe."""
    obj = ctx.obj
    return obj if isinstance(obj, _CliState) else _CliState()


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
        except (OSError, ValueError) as exc:
            # Best effort only: a console that refuses reconfiguration still
            # works, it just may mangle the banner glyphs.
            logging.getLogger("otacon.cli").debug("stream reconfigure failed: %r", exc)


_ensure_unicode_output()

# Restore default SIGPIPE so "otacon scan … | head" exits silently instead of
# printing BrokenPipeError. SIGPIPE doesn't exist on Windows.
if hasattr(_signal, "SIGPIPE"):
    _signal.signal(_signal.SIGPIPE, _signal.SIG_DFL)


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
    """Prints the Otacon ASCII banner."""
    console.print(BANNER)


def _version_callback(value: bool) -> None:
    """Typer eager callback for ``--version`` — prints the version and exits."""
    if value:
        from . import __version__

        console.print(f"[brand]otacon[/brand] [value]{__version__}[/value]")
        raise typer.Exit()


def _configure_logging(debug: bool) -> None:
    """Wires the ``otacon`` logger to a Rich handler. Off unless ``--debug``.

    Without this, the library's many graceful-degradation paths (WHOIS misses,
    DNS errors, HTTP timeouts) are invisible — this makes them surface at
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
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Print version and exit.",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        "-v",
        "--verbose",
        help="Log graceful-degradation events (DNS/WHOIS/HTTP failures) to stderr.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Disable UI, banner, and progress. Outputs JSON to stdout.",
    ),
) -> None:
    """Shows the banner before any command; enters interactive mode when run bare."""
    ctx.obj = _CliState(quiet=quiet)
    # Always assign (not just on quiet=True) so the module-level Console gets
    # reset between invocations — otherwise a prior --quiet run would silence
    # every subsequent command in long-running processes (e.g. test suites).
    console.quiet = quiet

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
        out.update(normalize_domain(d) for d in raw.split(",") if d.strip())
    if file:
        try:
            content = file.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise typer.BadParameter(f"exclude-file not found: {file}") from exc
        except OSError as exc:
            raise typer.BadParameter(f"cannot read exclude-file: {file}") from exc

        out.update(parse_domain_list(content))
    return out


def _load_domains(raw: list[str], file: Path | None) -> list[str]:
    """Merges positional domain args and --domains-file into a deduplicated, normalised list."""
    all_input: list[str] = list(raw)
    if file:
        try:
            content = file.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise typer.BadParameter(f"domains-file not found: {file}") from exc
        except OSError as exc:
            raise typer.BadParameter(f"cannot read domains-file: {file}") from exc
        for line in content.splitlines():
            entry = line.strip()
            if entry and not entry.startswith("#"):
                all_input.append(entry)

    seen: set[str] = set()
    result: list[str] = []
    for raw_domain in all_input:
        normalised = normalize_domain(raw_domain)
        if normalised and normalised not in seen:
            seen.add(normalised)
            result.append(normalised)
    return result


def _load_weights(file: Path | None) -> scoring.ScoringWeights:
    """Loads custom scoring weights from a JSON file if provided."""
    if not file:
        return scoring.ScoringWeights()
    try:
        import json

        content = file.read_text(encoding="utf-8")
        data = json.loads(content)
        return scoring.ScoringWeights(data)
    except FileNotFoundError as exc:
        raise typer.BadParameter(f"weights-file not found: {file}") from exc
    except (json.JSONDecodeError, ValueError, TypeError, OSError) as exc:
        raise typer.BadParameter(f"cannot read/parse weights-file: {file}. Error: {exc}") from exc


async def _run_scan(
    target: str,
    concurrency: int,
    check_http: bool,
    exclude: set[str] | None = None,
    quiet: bool = False,
    weights: scoring.ScoringWeights | None = None,
) -> ScanReport:
    """Runs a full scan; streams registered hits into a live table as they arrive."""
    return await run_scan(
        target,
        concurrency=concurrency,
        check_http=check_http,
        console=console,
        exclude=exclude,
        weights=weights,
        show_progress=not quiet,
    )


@app.command()
def scan(
    ctx: typer.Context,
    domain: list[str] = typer.Argument(
        default=None,
        help="Domain(s) to protect, e.g. example.com mycompany.com",
    ),
    domains_file: Path = typer.Option(
        None,
        "--domains-file",
        "-D",
        help="File with domains to scan (one per line, '#' = comment).",
    ),
    json_out: Path = typer.Option(None, "--json", help="Write the full JSON report to a file."),
    md_out: Path = typer.Option(
        None, "--markdown", "--md", help="Write the Markdown report to a file."
    ),
    html_out: Path = typer.Option(
        None, "--html", help="Write a self-contained HTML report to a file."
    ),
    csv_out: Path = typer.Option(None, "--csv", help="Write a CSV report to a file."),
    no_http: bool = typer.Option(
        False, "--no-http", help="Skip HTTP/SSL probing (faster, fewer signals)."
    ),
    concurrency: int = typer.Option(
        50, "--concurrency", "-c", help="Number of concurrent checks.", min=1, max=500
    ),
    show_all: bool = typer.Option(False, "--all", help="Show unregistered variants too."),
    exclude: str = typer.Option(
        None,
        "--exclude",
        "-x",
        help="Whitelist of domains to skip (comma-separated), e.g. legit aliases.",
    ),
    exclude_file: Path = typer.Option(
        None, "--exclude-file", help="File with a whitelist (one domain per line, '#' = comment)."
    ),
    fail_on: _Threshold = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 if any registered result meets or exceeds this risk level."
        " Choices: low medium high critical.",
    ),
    weights_file: Path = typer.Option(
        None, "--weights-file", "-w", help="Path to a JSON file overriding default scoring weights."
    ),
) -> None:
    """Scans domain variants and detects registered fakes."""
    quiet = _state(ctx).quiet
    domains = _load_domains(domain or [], domains_file)

    if not domains:
        console.print("[danger]Error: provide at least one domain to scan.[/danger]")
        raise typer.Exit(1)

    exclusions = _load_exclusions(exclude, exclude_file)
    weights = _load_weights(weights_file)

    all_reports: dict[str, ScanReport] = {}
    scan_errors: list[str] = []

    for d in domains:
        if not is_valid_domain(d):
            console.print(f"[warn]\u26a0 Skipping invalid domain: {escape(d)}[/warn]")
            scan_errors.append(d)
            continue

        console.print(f"[field]Target:[/field] [value]{escape(d)}[/value]")
        console.print(
            f"[muted]Mode: {'DNS only' if no_http else 'DNS + HTTP/SSL'} \u00b7 "
            f"concurrency: {concurrency}"
            + (f" \u00b7 whitelist: {len(exclusions)}" if exclusions else "")
            + "[/muted]"
        )

        try:
            report = run_async(
                _run_scan(
                    d,
                    concurrency,
                    check_http=not no_http,
                    exclude=exclusions,
                    quiet=quiet,
                    weights=weights,
                )
            )
        except KeyboardInterrupt:
            console.print("\n[muted]Interrupted.[/muted]")
            raise typer.Exit(1) from None
        except Exception as exc:
            console.print(f"[warn]⚠ Error scanning {escape(d)}: {escape(str(exc))}[/warn]")
            scan_errors.append(d)
            continue

        reporters.render_table(report, console, show_safe=show_all)
        all_reports[d] = report

    if not all_reports:
        raise typer.Exit(1)

    if len(domains) > 1:
        reporters.render_aggregate_summary(all_reports, scan_errors, console)

    multi = len(all_reports) > 1

    def _safe_write(path: Path, content: str, label: str) -> None:
        safe_path = safe_relative_path(str(path))
        if not safe_path:
            console.print(
                f"[danger]Error: refusing to write to unsafe path: {escape(str(path))}[/danger]"
            )
            return
        try:
            Path(safe_path).write_text(content, encoding="utf-8")
            console.print(f"[ok]\u2192 {label} saved:[/ok] [url]{escape(safe_path)}[/url]")
        except OSError as exc:
            console.print(f"[danger]Error saving {label}: {escape(str(exc))}[/danger]")

    if json_out:
        content = (
            reporters.aggregate_json(all_reports)
            if multi
            else reporters.to_json(next(iter(all_reports.values())))
        )
        _safe_write(json_out, content, "JSON")

    if md_out:
        if multi:
            console.print(
                "[muted]--markdown is not supported for multi-domain scans;"
                " use --json or --html.[/muted]"
            )
        else:
            _safe_write(md_out, reporters.to_markdown(next(iter(all_reports.values()))), "Markdown")

    if csv_out:
        if multi:
            console.print(
                "[muted]--csv is not supported for multi-domain scans;"
                " use --json or --html.[/muted]"
            )
        else:
            _safe_write(csv_out, reporters.to_csv(next(iter(all_reports.values()))), "CSV")

    if html_out:
        if multi:
            from .html_report import aggregate_html

            content = aggregate_html(all_reports)
        else:
            from .html_report import to_html

            content = to_html(next(iter(all_reports.values())))
        _safe_write(html_out, content, "HTML")

    if quiet:
        # Keyed off the reports we actually produced, not the domains requested:
        # asking for two domains and having one fail must still emit that one
        # report on stdout rather than falling between both branches.
        sys.stdout.write(
            (
                reporters.aggregate_json(all_reports)
                if multi
                else reporters.to_json(next(iter(all_reports.values())))
            )
            + "\n"
        )

    if fail_on is not None:
        threshold = RiskLevel(fail_on.value)
        if any(
            r.risk_level.rank >= threshold.rank
            for rep in all_reports.values()
            for r in rep.registered
        ):
            raise typer.Exit(2)


@app.command()
def generate(
    ctx: typer.Context,
    domain: str = typer.Argument(..., help="Domain to permute."),
    limit: int = typer.Option(0, "--limit", "-n", min=0, help="Display limit (0 = all)."),
    output: Path = typer.Option(
        None,
        "--output",
        "-o",
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
    quiet = _state(ctx).quiet
    domain = normalize_domain(domain)
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
            console.print(f"[danger]Error: unsafe path: {escape(str(output))}[/danger]")
        else:
            try:
                Path(safe_path).write_text(
                    "\n".join(p.domain for p in perms) + "\n", encoding="utf-8"
                )
                console.print(f"[ok]→ Wordlist saved:[/ok] [url]{escape(safe_path)}[/url]")
            except OSError as exc:
                console.print(f"[danger]Error saving wordlist: {escape(str(exc))}[/danger]")

    if quiet and not output:
        import json

        sys.stdout.write(json.dumps([p.domain for p in perms]) + "\n")


if __name__ == "__main__":
    app()
