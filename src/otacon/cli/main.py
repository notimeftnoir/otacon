"""Main Typer CLI application dispatching scan, generate, and diff subcommands."""

from __future__ import annotations

import io
import logging
import signal as _signal
import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console

from .._splash import play_intro
from ..triage.workflow import run as _interactive_run
from ..utils.theme import BANNER, OTACON_THEME
from .commands.diff import execute_diff
from .commands.generate import execute_generate
from .commands.scan import _CI, _FILTER, _NET, _OUT, execute_scan
from .commands.tui import execute_tui
from .state import _CliState


def _ensure_unicode_output() -> None:
    """Ensures console streams handle Unicode glyphs without crashing on legacy codepages."""
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
            logging.getLogger("otacon.cli").debug("stream reconfigure failed: %r", exc)


_ensure_unicode_output()

if hasattr(_signal, "SIGPIPE"):
    _signal.signal(_signal.SIGPIPE, _signal.SIG_DFL)


class _Threshold(str, Enum):
    """Severity threshold level for CI gating."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


app = typer.Typer(
    name="otacon",
    help=(
        "Find lookalike domains that imitate yours (typos, homoglyphs, other TLDs) "
        "and see which ones are registered and dangerous.\n\n"
        "Run [bold]otacon[/bold] with no arguments for a guided mode."
    ),
    epilog=(
        "[bold]Examples[/bold]\n\n"
        "  otacon scan example.com                          quick check\n\n"
        "  otacon scan example.com --html report.html       shareable report\n\n"
        "  otacon -q scan example.com --fail-on high        CI: JSON out, exit 2 on threats"
    ),
    rich_markup_mode="rich",
    add_completion=False,
)

console = Console(theme=OTACON_THEME)


def _banner(animate: bool = False) -> None:
    """Prints the Otacon banner with optional decoding animation."""
    from .. import __version__

    if animate:
        play_intro(console)
    else:
        console.print(BANNER, end="")
    console.print(
        f"  [muted]v{__version__} · find lookalike domains before attackers use them[/muted]\n"
    )


def _version_callback(value: bool) -> None:
    """Prints version and exits."""
    if value:
        from .. import __version__

        console.print(f"[brand]otacon[/brand] [value]{__version__}[/value]")
        raise typer.Exit()


def _configure_logging(debug: bool) -> None:
    """Configures structured stderr logging for library operations under --debug."""
    from rich.logging import RichHandler

    logger = logging.getLogger("otacon")
    logger.handlers.clear()
    if not debug:
        logger.addHandler(logging.NullHandler())
        return
    err_console = Console(stderr=True, theme=OTACON_THEME)
    handler = RichHandler(console=err_console, show_path=False, rich_tracebacks=True)
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
    """Shows banner before command execution or enters interactive guided mode when called bare."""
    ctx.obj = _CliState(quiet=quiet)
    console.quiet = quiet
    _configure_logging(debug)

    if not quiet:
        _banner(animate=ctx.invoked_subcommand is None)

    if ctx.invoked_subcommand is None:
        import sys

        inter_mod = sys.modules.get("otacon.interactive")
        inter_run = getattr(inter_mod, "run", _interactive_run) if inter_mod else _interactive_run
        inter_run(console)
        raise typer.Exit()


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
    json_out: Path = typer.Option(
        None, "--json", help="Write the full JSON report to a file.", rich_help_panel=_OUT
    ),
    md_out: Path = typer.Option(
        None,
        "--markdown",
        "--md",
        help="Write the Markdown report to a file.",
        rich_help_panel=_OUT,
    ),
    html_out: Path = typer.Option(
        None,
        "--html",
        help="Write a self-contained HTML report to a file.",
        rich_help_panel=_OUT,
    ),
    csv_out: Path = typer.Option(
        None, "--csv", help="Write a CSV report to a file.", rich_help_panel=_OUT
    ),
    no_http: bool = typer.Option(
        False,
        "--no-http",
        help="Skip HTTP/SSL probing (faster, fewer signals).",
        rich_help_panel=_NET,
    ),
    no_whois: bool = typer.Option(
        False,
        "--no-whois",
        help="Skip WHOIS / domain-age lookups (faster, avoids registry rate-limits).",
        rich_help_panel=_NET,
    ),
    no_dnsbl: bool = typer.Option(
        False,
        "--no-dnsbl",
        help="Skip passive DNSBL / Spamhaus DBL reputation lookups.",
        rich_help_panel=_NET,
    ),
    no_ct: bool = typer.Option(
        False,
        "--no-ct",
        help="Skip Certificate Transparency (CT logs) discovery.",
        rich_help_panel=_NET,
    ),
    concurrency: int = typer.Option(
        50,
        "--concurrency",
        "-c",
        help="Number of concurrent checks.",
        min=1,
        max=500,
        rich_help_panel=_NET,
    ),
    show_all: bool = typer.Option(
        False, "--all", help="Show unregistered variants too.", rich_help_panel=_FILTER
    ),
    exclude: str = typer.Option(
        None,
        "--exclude",
        "-x",
        help="Whitelist of domains to skip (comma-separated), e.g. legit aliases.",
        rich_help_panel=_FILTER,
    ),
    exclude_file: Path = typer.Option(
        None,
        "--exclude-file",
        help="File with a whitelist (one domain per line, '#' = comment).",
        rich_help_panel=_FILTER,
    ),
    fail_on: _Threshold = typer.Option(
        None,
        "--fail-on",
        help=(
            "Exit 2 if any registered result meets or exceeds this risk level. "
            "Choices: low medium high critical."
        ),
        rich_help_panel=_CI,
    ),
    weights_file: Path = typer.Option(
        None,
        "--weights-file",
        "-w",
        help="Path to a JSON file overriding default scoring weights.",
        rich_help_panel=_CI,
    ),
) -> None:
    """Scans domain variants and detects registered fakes."""
    execute_scan(
        ctx=ctx,
        console=console,
        domain=domain,
        domains_file=domains_file,
        json_out=json_out,
        md_out=md_out,
        html_out=html_out,
        csv_out=csv_out,
        no_http=no_http,
        no_whois=no_whois,
        no_dnsbl=no_dnsbl,
        no_ct=no_ct,
        concurrency=concurrency,
        show_all=show_all,
        exclude=exclude,
        exclude_file=exclude_file,
        fail_on=fail_on.value if fail_on is not None else None,
        weights_file=weights_file,
    )


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
    execute_generate(
        ctx=ctx,
        console=console,
        domain=domain,
        limit=limit,
        output=output,
        exclude=exclude,
        exclude_file=exclude_file,
    )


@app.command()
def diff(
    ctx: typer.Context,
    file1: Path = typer.Argument(..., help="Path to earlier JSON scan report."),
    file2: Path = typer.Argument(..., help="Path to newer JSON scan report."),
    json_out: Path = typer.Option(None, "--json", help="Export diff as JSON to a file."),
    fail_on_threats: bool = typer.Option(
        False, "--fail-on-threats", help="Exit code 2 if new high/critical threats detected."
    ),
) -> None:
    """Compares two Otacon scan reports to detect new registrations and threat shifts."""
    execute_diff(
        ctx=ctx,
        console=console,
        file1=file1,
        file2=file2,
        json_out=json_out,
        fail_on_threats=fail_on_threats,
    )


@app.command()
def tui(
    domain: str = typer.Argument(None, metavar="[domain]", help="Domain to scan, then triage."),
    report_file: Path = typer.Option(
        None, "--from", metavar="<path>", help="Triage a saved JSON report instead of scanning."
    ),
    concurrency: int = typer.Option(
        50, "--concurrency", "-c", min=1, max=500, metavar="<int>", help="Concurrent checks."
    ),
    no_http: bool = typer.Option(False, "--no-http", help="Skip HTTP/SSL probing."),
    no_whois: bool = typer.Option(False, "--no-whois", help="Skip WHOIS / domain-age lookups."),
    no_dnsbl: bool = typer.Option(False, "--no-dnsbl", help="Skip DNSBL reputation lookups."),
    no_ct: bool = typer.Option(False, "--no-ct", help="Skip Certificate Transparency discovery."),
) -> None:
    """Opens the keyboard-driven triage console on a scan or a saved report."""
    execute_tui(
        console=console,
        domain=domain,
        report_file=report_file,
        concurrency=concurrency,
        check_http=not no_http,
        check_whois=not no_whois,
        check_dnsbl=not no_dnsbl,
        check_ct=not no_ct,
    )


if __name__ == "__main__":
    app()
