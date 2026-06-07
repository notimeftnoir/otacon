"""Interactive entry point — prompts for domain and options when otacon is run bare."""
from __future__ import annotations

import asyncio
import webbrowser
from pathlib import Path
from urllib.parse import urlparse

import questionary
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.shortcuts import prompt as _pt_prompt
from prompt_toolkit.validation import ValidationError, Validator
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
from .models import DomainResult, Permutation, ScanReport
from .resolver import _DEFAULT_CONCURRENCY, Resolver
from .whois import fetch_domain_age, format_age

_POINTER = "[*]"
_QMARK = "›"


def _make_style(answer_color: str) -> questionary.Style:
    return questionary.Style([
        ("qmark",             "fg:#00d7af bold"),
        ("question",          "bold fg:#afafaf"),
        ("answer",            f"fg:{answer_color}"),
        ("pointer",           "fg:#00d7af bold"),
        ("highlighted",       "fg:#00d7af bold"),
        ("selected",          f"fg:{answer_color}"),
        ("instruction",       "fg:#8a8a8a"),
        ("text",              f"fg:{answer_color}"),
        ("disabled",          "fg:#8a8a8a italic"),
        ("validator-toolbar", "bg:#870000 fg:#ffffff"),
    ])


_STYLE = _make_style("#ffffff")
_STYLE_DOMAIN = _make_style("#5fd700")


class _YNValidator(Validator):
    def validate(self, document) -> None:
        if document.text.strip().lower() not in ("y", "n", ""):
            raise ValidationError(message="Type y or n", cursor_position=len(document.text))


def _yn_bindings() -> KeyBindings:
    """Key bindings that auto-submit on y/n without requiring Enter."""
    kb = KeyBindings()

    @kb.add("y")
    @kb.add("Y")
    def _yes(event) -> None:
        event.app.current_buffer.text = "y"
        event.app.current_buffer.validate_and_handle()

    @kb.add("n")
    @kb.add("N")
    def _no(event) -> None:
        event.app.current_buffer.text = "n"
        event.app.current_buffer.validate_and_handle()

    return kb


def _confirm(message: str) -> bool | None:
    """y/n prompt: green y, red n, auto-submits on keypress. Returns True/False/None (Ctrl+C)."""
    prompt_text = FormattedText([
        ("fg:#00d7af bold", "› "),
        ("bold fg:#afafaf", f"{message} ("),
        ("fg:#5fd700 bold", "y"),
        ("fg:#8a8a8a", "/"),
        ("fg:#ff5f5f bold", "n"),
        ("fg:#8a8a8a", ") "),
    ])
    try:
        answer = _pt_prompt(
            prompt_text,
            validator=_YNValidator(),
            validate_while_typing=False,
            key_bindings=_yn_bindings(),
        )
        return answer.strip().lower() == "y"
    except KeyboardInterrupt:
        return None


def _validate_domain(text: str) -> bool | str:
    if not text.strip():
        return "Domain cannot be empty"
    return True


def _validate_limit(text: str) -> bool | str:
    try:
        if int(text) < 0:
            return "Enter 0 or greater"
        return True
    except ValueError:
        return "Enter a number (0 = all)"


def run(console: Console) -> None:
    """Called by cli._main when otacon is invoked with no subcommand."""
    domain = questionary.text(
        "Enter your domain:", validate=_validate_domain, qmark=_QMARK, style=_STYLE_DOMAIN
    ).ask()
    if domain is None:
        return
    domain = domain.strip().lower().removeprefix("www.")

    mode = questionary.select(
        "Mode:",
        choices=[
            questionary.Choice(
                "scan    — DNS + HTTP, detects registered variants", value="scan"
            ),
            questionary.Choice(
                "generate — offline variants, no network", value="generate"
            ),
        ],
        pointer=_POINTER,
        qmark=_QMARK,
        style=_STYLE,
    ).ask()
    if mode is None:
        return

    if mode == "scan":
        _interactive_scan(domain, console)
    else:
        _interactive_generate(domain, console)


def _interactive_scan(domain: str, console: Console) -> None:
    network = questionary.select(
        "Network:",
        choices=[
            questionary.Choice("DNS + HTTP  (full, slower)", value="full"),
            questionary.Choice("DNS only    (fast)", value="dns"),
        ],
        pointer=_POINTER,
        qmark=_QMARK,
        style=_STYLE,
    ).ask()
    if network is None:
        return

    show_all = _confirm("Show unregistered variants?")
    if show_all is None:
        return

    check_http = network == "full"
    exclusions: set[str] = set()
    whitelist_path = Path("whitelist.txt")
    if whitelist_path.exists():
        try:
            for line in whitelist_path.read_text(encoding="utf-8").splitlines():
                entry = line.strip().lower()
                if entry and not entry.startswith("#"):
                    exclusions.add(entry)
        except OSError:
            pass

    report = run_async(
        _scan(domain, concurrency=_DEFAULT_CONCURRENCY, check_http=check_http,
              console=console, exclude=exclusions or None)
    )
    reporters.render_table(report, console, show_safe=show_all)
    _suggest_defensive_whitelist(report, console)
    _action_loop(report, domain, console, check_http=check_http)


def _interactive_generate(domain: str, console: Console) -> None:
    limit_str = questionary.text(
        "Result limit (0 = all):", default="0", validate=_validate_limit,
        qmark=_QMARK, style=_STYLE,
    ).ask()
    if limit_str is None:
        return

    limit = int(limit_str)
    perms = permutations.generate(domain)
    shown = perms[:limit] if limit > 0 else perms

    console.print(
        f"[field]Generated[/field] [value]{len(perms)}[/value] "
        f"[field]variants for[/field] [value]{escape(domain)}[/value]\n"
    )
    for p in shown:
        console.print(
            f"  [value]{escape(p.domain):<40}[/value]"
            f" [muted]{p.kind.value:<12} {escape(p.note)}[/muted]"
        )
    if limit and len(perms) > limit:
        console.print(f"\n[muted]... and {len(perms) - limit} more[/muted]")


def _show_whois(result: DomainResult, console: Console) -> None:
    """Displays WHOIS registration info for a domain result."""
    console.print(f"\n[field]WHOIS:[/field] [value]{escape(result.domain)}[/value]")
    created, age = result.created_at, result.age_days
    if created is None:
        console.print("[muted]Fetching WHOIS…[/muted]")
        created, age = run_async(fetch_domain_age(result.domain))
    if created is not None:
        console.print(f"  [field]Created:[/field]  [value]{created:%Y-%m-%d}[/value]")
        console.print(f"  [field]Age:[/field]     [value]{format_age(age)}[/value]")
    else:
        console.print("  [muted]WHOIS data unavailable for this domain[/muted]")
    if result.ip_addresses:
        ips = ", ".join(result.ip_addresses[:3])
        console.print(f"  [field]IPs:[/field]     [value]{ips}[/value]")
    if result.mx_records:
        mx = ", ".join(result.mx_records[:3])
        console.print(f"  [field]MX:[/field]      [value]{mx}[/value]")
    console.print()


def _export_result(result: DomainResult, console: Console) -> None:
    """Saves a single domain result as a JSON file.
    
    Validates filename to prevent path traversal attacks (e.g., ../../../etc/passwd).
    """
    default_name = f"{result.domain.replace('.', '_')}.json"
    filename = questionary.text(
        "Save as:", default=default_name, qmark=_QMARK, style=_STYLE,
    ).ask()
    if filename is None:
        return
    
    try:
        # Sanitize: reject parent directory traversal patterns
        if ".." in filename:
            console.print(f"[danger]Error: Path traversal detected — use relative paths[/danger]")
            return
        
        # Resolve to canonical path
        file_path = Path(filename).resolve()
        
        # Write the file
        file_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"[ok]→ Saved:[/ok] [url]{escape(file_path.name)}[/url]")
    except (OSError, ValueError) as exc:
        console.print(f"[danger]Error: {exc}[/danger]")


def _rescan_result(
    result: DomainResult, target: str, check_http: bool, console: Console
) -> DomainResult:
    """Re-runs a network check for a single variant and returns the updated scored result."""
    perm = Permutation(domain=result.domain, kind=result.kind, note=result.note)
    console.print(f"[muted]Rescanning {escape(result.domain)}…[/muted]")

    async def _run() -> DomainResult:
        async with Resolver(check_http=check_http) as resolver:
            return await resolver.check_one(perm)

    raw = run_async(_run())
    return scoring.score(raw, target)


def _suggest_defensive_whitelist(report: ScanReport, console: Console) -> None:
    """After a scan, if ⚑ defensive domains were found, offer to write them to whitelist.txt."""
    defensive = [r for r in report.registered if r.is_likely_defensive]
    if not defensive:
        return
    console.print(
        f"[warn]⚑  {len(defensive)} domain(s) appear defensive "
        f"(redirect → original). Add to whitelist?[/warn]"
    )
    if _confirm("Write to whitelist.txt?") is not True:
        return
    path = Path("whitelist.txt")
    existing = set(path.read_text(encoding="utf-8").splitlines()) if path.exists() else set()
    new_entries = [r.domain for r in defensive if r.domain not in existing]
    if new_entries:
        with path.open("a", encoding="utf-8") as f:
            for d in new_entries:
                f.write(d + "\n")
        console.print(f"[ok]→ Added {len(new_entries)} domain(s) to {path}[/ok]")
    else:
        console.print("[muted]All already in whitelist.[/muted]")


def _action_loop(
    report: ScanReport, domain: str, console: Console, check_http: bool
) -> None:
    """Post-scan action loop — pick a registered domain row, then act on it.

    Loops until the user chooses quit or presses Ctrl+C.
    """
    session_allowed: set[str] = set()

    while True:
        candidates = sorted(
            [r for r in report.registered if r.domain not in session_allowed],
            key=lambda r: r.risk_score,
            reverse=True,
        )
        if not candidates:
            break

        domain_choices = [
            questionary.Choice(
                f"{r.domain:<40} [{r.risk_level.value}]  score: {r.risk_score}",
                value=r,
            )
            for r in candidates
        ] + [questionary.Choice("── quit ──")]

        selected = questionary.select(
            "Domain:", choices=domain_choices, pointer=_POINTER, qmark=_QMARK, style=_STYLE,
        ).ask()

        if not isinstance(selected, DomainResult):
            break

        while True:
            action = questionary.select(
                f"Action for {selected.domain}:",
                choices=[
                    questionary.Choice("[o]pen   — open in browser", value="open"),
                    questionary.Choice("[w]hois  — show registration info", value="whois"),
                    questionary.Choice("[e]xport — save result as JSON", value="export"),
                    questionary.Choice("[a]llow  — skip in this session", value="allow"),
                    questionary.Choice("[r]escan — re-check this domain now", value="rescan"),
                    questionary.Choice("[b]ack   — pick a different domain", value="back"),
                    questionary.Choice("[q]uit   — exit actions", value="quit"),
                ],
                pointer=_POINTER,
                qmark=_QMARK,
                style=_STYLE,
            ).ask()

            if action is None or action == "quit":
                return

            if action == "back":
                break

            if action == "open":
                url = f"https://{selected.domain}"
                webbrowser.open(url)
                console.print(f"[ok]→ Opened[/ok] [url]{url}[/url]")

            elif action == "whois":
                _show_whois(selected, console)

            elif action == "export":
                _export_result(selected, console)

            elif action == "allow":
                session_allowed.add(selected.domain)
                console.print(
                    f"[ok]✓ {escape(selected.domain)} added to session whitelist[/ok]"
                )
                break  # back to domain picker; domain now filtered out

            elif action == "rescan":
                updated = _rescan_result(selected, domain, check_http, console)
                for i, r in enumerate(report.results):
                    if r.domain == selected.domain:
                        report.results[i] = updated
                        break
                selected = updated
                reporters.render_table(
                    ScanReport(target=domain, total_permutations=1, results=[updated]),
                    console,
                    show_safe=True,
                )
                if not updated.is_registered:
                    break  # domain went offline — return to domain picker


async def _scan(
    domain: str, concurrency: int, check_http: bool, console: Console,
    exclude: set[str] | None = None,
) -> ScanReport:
    perms = permutations.generate(domain, exclude=exclude)
    report = ScanReport(target=domain, total_permutations=len(perms))
    if not perms:
        return report

    hits: list[DomainResult] = []

    progress = Progress(
        SpinnerColumn(style="brand"),
        TextColumn("[field]{task.description}"),
        BarColumn(complete_style="brand", finished_style="ok"),
        TextColumn("[muted]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    )
    task_id = progress.add_task("Checking variants", total=len(perms))

    with Live(progress, console=console, refresh_per_second=4, transient=True) as live:
        async with Resolver(concurrency=concurrency, check_http=check_http) as resolver:
            coros = [resolver.check_one(p) for p in perms]
            for coro in asyncio.as_completed(coros):
                result = await coro
                scored = scoring.score(result, domain)
                report.results.append(scored)
                progress.advance(task_id)
                if scored.is_registered:
                    hits.append(scored)
                    live.update(Group(progress, reporters.build_live_table(hits, domain)))

    return report
