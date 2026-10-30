"""Interactive scan workflows and domain triage orchestrator."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import questionary
from rich.console import Console
from rich.markup import escape

from .._asyncutils import run_async
from ..core.models import DomainResult, ScanReport
from ..engine.scanner import run_scan
from ..net.resolver import DEFAULT_CONCURRENCY
from ..permutations.generator import generate
from ..reporters import console as reporters
from ..utils.validate import normalize_domain, parse_domain_list
from .actions import (
    _ACTION_CHOICES,
    _ACTION_HANDLERS,
    _ActionContext,
    _ActionResult,
    _suggest_defensive_whitelist,
)
from .dossier import _dossier
from .prompts import (
    _POINTER,
    _QMARK,
    _STYLE,
    _STYLE_DOMAIN,
    _confirm,
    _validate_domain,
    _validate_limit,
)

_log = logging.getLogger("otacon.triage.workflow")


# ponytail: test hook — the guided mode's tests patch the otacon.interactive facade
# (~80 sites), so lookups go through it. Repoint those patches to the real
# modules and this goes; until then it is confined to triage/.
def _get_inter(name: str, fallback: Any) -> Any:
    import sys

    mod = sys.modules.get("otacon.interactive")
    if mod and hasattr(mod, name):
        val = getattr(mod, name)
        if val is not fallback:
            return val
    return fallback


def _pick_domain(report: ScanReport, session_allowed: set[str]) -> DomainResult | None:
    """Renders the domain picker and returns the chosen result."""
    candidates = sorted(
        [r for r in report.registered if r.domain not in session_allowed],
        key=lambda r: r.risk_score,
        reverse=True,
    )
    if not candidates:
        return None
    choices = [
        questionary.Choice(
            f"{r.risk_level.icon} {r.domain:<40} {r.risk_level.value:<9} {r.risk_score:>3}",
            value=r,
        )
        for r in candidates
    ] + [questionary.Choice("── quit ──")]
    q_mod = _get_inter("questionary", questionary)
    selected = q_mod.select(
        "Pick a domain to inspect (riskiest first):",
        choices=choices,
        pointer=_POINTER,
        qmark=_QMARK,
        style=_STYLE,
    ).ask()
    return selected if isinstance(selected, DomainResult) else None


def _run_action_menu(ctx: _ActionContext) -> str:
    """Prompts for actions on ctx.selected until handler signals NEXT_DOMAIN or QUIT."""
    ctx.console.print(_dossier(ctx.selected))
    while True:
        q_mod = _get_inter("questionary", questionary)
        action = q_mod.select(
            f"Action for {ctx.selected.domain}:",
            choices=_ACTION_CHOICES,
            pointer=_POINTER,
            qmark=_QMARK,
            style=_STYLE,
        ).ask()
        if action is None or action == "quit":
            return _ActionResult.QUIT
        if action == "back":
            return _ActionResult.NEXT_DOMAIN
        handler = _ACTION_HANDLERS.get(action)
        if handler is None:
            continue
        outcome = handler(ctx)
        if outcome != _ActionResult.CONTINUE:
            return outcome


def _action_loop(report: ScanReport, domain: str, console: Console, check_http: bool) -> None:
    """Post-scan interactive triage loop."""
    session_allowed: set[str] = set()
    while True:
        selected = _pick_domain(report, session_allowed)
        if selected is None:
            return
        ctx = _ActionContext(
            selected=selected,
            target=domain,
            check_http=check_http,
            report=report,
            session_allowed=session_allowed,
            console=console,
        )
        if _run_action_menu(ctx) == _ActionResult.QUIT:
            return


async def _scan(
    domain: str,
    concurrency: int,
    check_http: bool,
    console: Console,
    exclude: set[str] | None = None,
) -> ScanReport:
    """Asynchronous scanning delegate."""
    return await run_scan(
        domain,
        concurrency=concurrency,
        check_http=check_http,
        console=console,
        exclude=exclude,
    )


def _interactive_scan(domain: str, console: Console) -> None:
    """Guided scan workflow."""
    q_mod = _get_inter("questionary", questionary)
    network = q_mod.select(
        "How thorough?",
        choices=[
            questionary.Choice(
                "Full      DNS + websites + certificates, about a minute", value="full"
            ),
            questionary.Choice("Quick     DNS only, a few seconds, fewer clues", value="dns"),
        ],
        pointer=_POINTER,
        qmark=_QMARK,
        style=_STYLE,
    ).ask()
    if network is None:
        return

    confirm_fn = _get_inter("_confirm", _confirm)
    show_all = confirm_fn("Also list lookalikes nobody has registered?")
    if show_all is None:
        return

    check_http = network == "full"
    exclusions: set[str] = set()
    whitelist_path = Path("whitelist.txt")
    if whitelist_path.exists():
        try:
            exclusions = parse_domain_list(whitelist_path.read_text(encoding="utf-8"))
        except OSError as exc:
            _log.debug("Could not read whitelist.txt: %s", exc)

    scan_fn = _get_inter("_scan", _scan)
    report = run_async(
        scan_fn(
            domain,
            concurrency=DEFAULT_CONCURRENCY,
            check_http=check_http,
            console=console,
            exclude=exclusions or None,
        )
    )
    reporters_mod = _get_inter("reporters", reporters)
    reporters_mod.render_table(report, console, show_safe=show_all)
    suggest_fn = _get_inter("_suggest_defensive_whitelist", _suggest_defensive_whitelist)
    suggest_fn(report, console)
    action_loop_fn = _get_inter("_action_loop", _action_loop)
    action_loop_fn(report, domain, console, check_http=check_http)


def _interactive_generate(domain: str, console: Console) -> None:
    """Guided offline generation workflow."""
    q_mod = _get_inter("questionary", questionary)
    limit_str = q_mod.text(
        "Result limit (0 = all):",
        default="0",
        validate=_validate_limit,
        qmark=_QMARK,
        style=_STYLE,
    ).ask()
    if limit_str is None:
        return

    limit = int(limit_str)
    perms_mod = _get_inter("permutations", None)
    gen_fn = getattr(perms_mod, "generate", generate) if perms_mod else generate
    perms = gen_fn(domain)
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


def run(console: Console) -> None:
    """Interactive root entry point when invoked without CLI subcommands."""
    console.print(
        "[muted]Type the domain you want to protect. Otacon builds the lookalikes an "
        "attacker could register and checks which ones exist.[/muted]\n"
    )
    q_mod = _get_inter("questionary", questionary)
    domain = q_mod.text(
        "Your domain (e.g. example.com):",
        validate=_validate_domain,
        qmark=_QMARK,
        style=_STYLE_DOMAIN,
    ).ask()
    if domain is None:
        return
    domain = normalize_domain(domain)

    mode = q_mod.select(
        "What should I do?",
        choices=[
            questionary.Choice(
                "Scan      find registered lookalikes and rate the risk (recommended)",
                value="scan",
            ),
            questionary.Choice(
                "Generate  just list possible lookalikes, offline", value="generate"
            ),
        ],
        pointer=_POINTER,
        qmark=_QMARK,
        style=_STYLE,
    ).ask()
    if mode is None:
        return

    if mode == "scan":
        interactive_scan_fn = _get_inter("_interactive_scan", _interactive_scan)
        interactive_scan_fn(domain, console)
    else:
        interactive_gen_fn = _get_inter("_interactive_generate", _interactive_generate)
        interactive_gen_fn(domain, console)


__all__ = [
    "_action_loop",
    "_interactive_generate",
    "_interactive_scan",
    "_pick_domain",
    "_run_action_menu",
    "_scan",
    "run",
]
