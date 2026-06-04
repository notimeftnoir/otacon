"""Interactive entry point — prompts for domain and options when otacon is run bare."""
from __future__ import annotations

import asyncio

import questionary
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.shortcuts import prompt as _pt_prompt
from prompt_toolkit.validation import ValidationError, Validator
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
from .resolver import _DEFAULT_CONCURRENCY, Resolver

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
    domain = domain.strip()

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
    report = asyncio.run(
        _scan(domain, concurrency=_DEFAULT_CONCURRENCY, check_http=check_http, console=console)
    )
    reporters.render_table(report, console, show_safe=show_all)


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


async def _scan(domain: str, concurrency: int, check_http: bool, console: Console) -> ScanReport:
    perms = permutations.generate(domain)
    report = ScanReport(target=domain, total_permutations=len(perms))
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
            coros = [resolver.check_one(p) for p in perms]
            for coro in asyncio.as_completed(coros):
                result = await coro
                report.results.append(scoring.score(result, domain))
                progress.advance(task)

    return report
