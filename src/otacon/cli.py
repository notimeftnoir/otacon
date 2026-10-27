"""Typer CLI entry point: ``scan``, ``generate``, plus bare-call interactive mode."""

from __future__ import annotations

import dataclasses
import io
import json
import logging
import signal as _signal
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import permutations, reporters, scoring, soc
from ._asyncutils import run_async
from ._scanner import run_scan
from ._splash import play_intro
from ._validate import (
    is_valid_domain,
    normalize_domain,
    parse_domain_list,
    safe_cli_path,
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
    """Keeps the Unicode UI (●, █, ✓, →) from crashing non-UTF-8 consoles.

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

_OUT, _NET, _FILTER, _CI = "Reports", "Network", "Filtering", "Scoring & CI"

console = Console(theme=OTACON_THEME)


def _banner(animate: bool = False) -> None:
    """Prints the Otacon banner; *animate* plays the decode intro first."""
    from . import __version__

    if animate:
        play_intro(console)
    else:
        console.print(BANNER, end="")
    console.print(
        f"  [muted]v{__version__} · find lookalike domains before attackers use them[/muted]\n"
    )


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
    # A dedicated stderr console: the UI `console` writes to stdout and is
    # silenced by --quiet, which would mix the log into the results table or,
    # under `-q -v`, drop it entirely.
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
    """Shows the banner before any command; enters interactive mode when run bare."""
    ctx.obj = _CliState(quiet=quiet)
    # Always assign (not just on quiet=True) so the module-level Console gets
    # reset between invocations — otherwise a prior --quiet run would silence
    # every subsequent command in long-running processes (e.g. test suites).
    console.quiet = quiet

    _configure_logging(debug)
    if not quiet:
        # Motion only for the guided mode: a person is watching there, while
        # subcommands are often scripted and should start instantly.
        _banner(animate=ctx.invoked_subcommand is None)

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


def _validate_resolvers(values: list[str] | None) -> list[str]:
    """Typer callback: every --resolver must be a literal IPv4/IPv6 address."""
    import ipaddress

    for v in values or []:
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise typer.BadParameter(f"not an IP address: {v}") from exc
    return values or []


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
    check_whois: bool = True,
    nameservers: list[str] | None = None,
    check_intel: bool = True,
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
        check_whois=check_whois,
        nameservers=nameservers,
        check_intel=check_intel,
    )


def _send_syslog(lines: list[str], destination: str) -> None:
    """Sends syslog *lines*, reporting the outcome instead of raising."""
    try:
        sent = soc.send_syslog(lines, destination)
    except (OSError, ValueError) as exc:
        console.print(f"[danger]Error sending to syslog: {escape(str(exc))}[/danger]")
        return
    console.print(
        f"[ok]→ Syslog:[/ok] [muted]{sent} event(s) sent to {escape(destination)}[/muted]"
    )


def _print_next_steps(reports: dict[str, ScanReport], html_written: bool, ci_gated: bool) -> None:
    """Up to three follow-up commands that fit this result, gh/vercel style.

    Newcomers rarely find --html or the guided mode on their own; a hint at
    the moment they would want it costs one glance and is silenced by -q.
    """
    domain = escape(next(iter(reports)))
    found = any(r.registered for r in reports.values())
    dangerous = any(
        t.risk_level.rank >= RiskLevel.HIGH.rank for r in reports.values() for t in r.threats
    )
    tips: list[tuple[str, str]] = []
    if found and not html_written:
        tips.append(
            (f"otacon scan {domain} --html report.html", "a report to share with your team")
        )
    if dangerous:
        tips.append(("otacon", "guided mode: WHOIS, takedown notice, whitelist"))
    if not ci_gated:
        tips.append(
            (f"otacon -q scan {domain} --fail-on high", "automate it in CI or a nightly job")
        )

    grid = Table.grid(padding=(0, 2))
    for cmd, why in tips[:3]:
        grid.add_row("[brand]•[/brand]", f"[bold white]{cmd}[/bold white]", f"[muted]{why}[/muted]")
    console.print("[field]Next steps[/field]")
    console.print(grid)
    console.print()


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
    stix_out: Path = typer.Option(
        None,
        "--stix",
        help="Write a STIX 2.1 bundle (threat-intel platforms).",
        rich_help_panel=_OUT,
    ),
    misp_out: Path = typer.Option(
        None, "--misp", help="Write a MISP event (Import from > MISP JSON).", rich_help_panel=_OUT
    ),
    syslog: str = typer.Option(
        None,
        "--syslog",
        help="Send medium+ findings to a SIEM, e.g. udp://wazuh.lan:514 or tcp://host:514.",
        rich_help_panel=_OUT,
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
    resolvers: list[str] = typer.Option(
        None,
        "--resolver",
        "-r",
        help="DNS server IP to use instead of the system one; repeatable."
        " Try 1.1.1.1 if your router drops queries.",
        callback=_validate_resolvers,
    ),
    no_intel: bool = typer.Option(
        False,
        "--no-intel",
        help="Skip threat-intel feeds (OpenPhish, Phishing Army) and the URLhaus lookup.",
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
        help="Exit 2 if any registered result meets or exceeds this risk level."
        " Choices: low medium high critical.",
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
            console.print(f"[warn]⚠ Skipping invalid domain: {escape(d)}[/warn]")
            scan_errors.append(d)
            continue

        console.print(f"\n[brand]►[/brand] Scanning [bold white]{escape(d)}[/bold white]")
        console.print(
            f"  [muted]{'DNS only' if no_http else 'DNS + HTTP/SSL'}"
            + (" · WHOIS off" if no_whois else " · WHOIS")
            + f" · {concurrency} parallel checks"
            + (f" · whitelist: {len(exclusions)}" if exclusions else "")
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
                    check_whois=not no_whois,
                    nameservers=resolvers or None,
                    check_intel=not no_intel,
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
        target_path = safe_cli_path(str(path))
        if not target_path:
            console.print(
                f"[danger]Error: refusing to write to unsafe path: {escape(str(path))}[/danger]"
            )
            return
        try:
            dest = Path(target_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
            console.print(f"[ok]→ {label} saved:[/ok] [url]{escape(target_path)}[/url]")
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

    if stix_out:
        _safe_write(stix_out, soc.to_stix(list(all_reports.values())), "STIX")
    if misp_out:
        _safe_write(misp_out, soc.to_misp(list(all_reports.values())), "MISP")
    if syslog:
        lines = [line for rep in all_reports.values() for line in soc.syslog_lines(rep)]
        _send_syslog(lines, syslog)

    _print_next_steps(all_reports, html_written=bool(html_out), ci_gated=fail_on is not None)

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


_EVENT_STYLE = {"new": "danger", "escalated": "warn", "gone": "ok", "discovered": "info"}


@app.command()
def watch(
    ctx: typer.Context,
    domain: list[str] = typer.Argument(default=None, help="Domain(s) to watch."),
    domains_file: Path = typer.Option(
        None, "--domains-file", "-D", help="File with domains to watch (one per line)."
    ),
    webhook: list[str] = typer.Option(
        None,
        "--webhook",
        envvar="OTACON_WEBHOOK",
        help="Slack, Discord, Teams or any URL taking JSON; repeatable. Prefer the"
        " OTACON_WEBHOOK variable so the secret stays out of shell history.",
    ),
    state: Path = typer.Option(
        None, "--state", help="SQLite state file (default: per-user data directory)."
    ),
    exit_code: bool = typer.Option(
        False, "--exit-code", help="Exit 2 when anything changed (for CI and schedulers)."
    ),
    no_http: bool = typer.Option(False, "--no-http", help="Skip HTTP/SSL probing."),
    no_whois: bool = typer.Option(False, "--no-whois", help="Skip WHOIS / RDAP lookups."),
    no_intel: bool = typer.Option(False, "--no-intel", help="Skip threat intel and CT."),
    resolvers: list[str] = typer.Option(
        None, "--resolver", "-r", help="DNS server IP to use.", callback=_validate_resolvers
    ),
    concurrency: int = typer.Option(50, "--concurrency", "-c", min=1, max=500),
    exclude: str = typer.Option(None, "--exclude", "-x", help="Whitelist, comma-separated."),
    exclude_file: Path = typer.Option(None, "--exclude-file", help="Whitelist file."),
    syslog: str = typer.Option(
        None, "--syslog", help="Also send change events to a SIEM: udp://host:514 or tcp://..."
    ),
) -> None:
    """Scans and reports only what changed since the last run; alerts webhooks.

    Meant for cron, the Task Scheduler or a scheduled GitHub Action. The first
    run of each domain records a baseline and alerts nothing.
    """
    from . import watch as watching

    quiet = _state(ctx).quiet
    domains = _load_domains(domain or [], domains_file)
    if not domains or not all(is_valid_domain(d) for d in domains):
        console.print("[danger]Error: provide valid domain(s) to watch.[/danger]")
        raise typer.Exit(1)
    exclusions = _load_exclusions(exclude, exclude_file)
    store = watching.State(state or watching.default_state_path())
    changed: dict[str, list[watching.Event]] = {}
    try:
        for d in domains:
            console.print(f"\n[brand]►[/brand] Watching [bold white]{escape(d)}[/bold white]")
            report = run_async(
                _run_scan(
                    d,
                    concurrency,
                    check_http=not no_http,
                    exclude=exclusions,
                    quiet=quiet,
                    check_whois=not no_whois,
                    nameservers=resolvers or None,
                    check_intel=not no_intel,
                )
            )
            baseline = not store.has_baseline(d)
            events = [] if baseline else store.diff(report)
            store.save(report)
            if baseline:
                console.print(
                    f"[ok]✓ Baseline saved:[/ok] {len(report.registered)} registered lookalikes,"
                    f" {len(report.discovered)} discovered hosts. Changes alert from the next run."
                )
            elif not events:
                console.print("[ok]✓ No changes since the last run.[/ok]")
            else:
                changed[d] = events
                for e in events:
                    console.print(
                        f"  [{_EVENT_STYLE[e.kind]}]{e.kind.upper():<10}[/]"
                        f" [value]{escape(e.domain)}[/value] [muted]{escape(e.detail)}[/muted]"
                    )
    finally:
        store.close()

    if changed and syslog:
        _send_syslog([line for t, ev in changed.items() for line in soc.watch_lines(t, ev)], syslog)

    # An unset CI secret arrives as an empty OTACON_WEBHOOK, not as no value.
    urls = [u.strip() for u in webhook or [] if u.strip()]
    if changed and urls:

        async def _send() -> list[bool]:
            async with httpx.AsyncClient() as client:
                return [
                    await watching.notify(client, url, target, events)
                    for target, events in changed.items()
                    for url in urls
                ]

        sent = run_async(_send())
        console.print(f"[muted]Webhooks: {sum(sent)}/{len(sent)} delivered.[/muted]")

    if quiet:
        sys.stdout.write(
            json.dumps(
                {t: [dataclasses.asdict(e) for e in ev] for t, ev in changed.items()}, indent=2
            )
            + "\n"
        )
    if exit_code and changed:
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
        import json

        sys.stdout.write(json.dumps([p.domain for p in perms]) + "\n")


if __name__ == "__main__":
    app()
