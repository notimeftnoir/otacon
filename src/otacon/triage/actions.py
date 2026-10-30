"""Interactive triage actions for domain threat investigation and remediation."""

from __future__ import annotations

import webbrowser
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote

import questionary
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.text import Text

from .._asyncutils import run_async
from ..core.models import DomainResult, Permutation, ScanOptions, ScanReport
from ..net.resolver import Resolver
from ..net.whois import fetch_domain_age, format_age
from ..reporters import console as reporters
from ..scoring import engine as scoring
from ..utils.theme import GLYPH_DEFENSIVE
from ..utils.validate import (
    normalize_domain,
    parse_domain_list,
    safe_relative_path,
)
from .notice import build_takedown_notice
from .prompts import _QMARK, _STYLE, _confirm


def _get_inter(name: str, fallback: Any) -> Any:
    import sys

    mod = sys.modules.get("otacon.interactive")
    if mod and hasattr(mod, name):
        val = getattr(mod, name)
        if val is not fallback:
            return val
    return fallback


def _show_whois(result: DomainResult, console: Console) -> None:
    """Displays WHOIS registration info for a domain result."""
    console.print(f"\n[field]WHOIS:[/field] [value]{escape(result.domain)}[/value]")
    created, age = result.created_at, result.age_days
    if created is None:
        console.print("[muted]Fetching WHOIS…[/muted]")
        whois_fn = _get_inter("fetch_domain_age", fetch_domain_age)
        created, age = run_async(whois_fn(result.domain))
    if created is not None:
        console.print(f"  [field]Created:[/field]  [value]{created:%Y-%m-%d}[/value]")
        console.print(f"  [field]Age:[/field]     [value]{format_age(age)}[/value]")
    else:
        console.print("  [muted]WHOIS data unavailable for this domain[/muted]")
    if result.ip_addresses:
        ips = ", ".join(result.ip_addresses[:3])
        console.print(f"  [field]IPs:[/field]     [value]{escape(ips)}[/value]")
    if result.mx_records:
        mx = ", ".join(result.mx_records[:3])
        console.print(f"  [field]MX:[/field]      [value]{escape(mx)}[/value]")
    console.print()


def _export_result(result: DomainResult, console: Console) -> None:
    """Saves a single domain result as a JSON file under the current directory."""
    default_name = f"{result.domain.replace('.', '_')}.json"
    q_mod = _get_inter("questionary", questionary)
    filename = q_mod.text(
        "Save as:",
        default=default_name,
        qmark=_QMARK,
        style=_STYLE,
    ).ask()
    if filename is None:
        return

    safe_path = safe_relative_path(filename)
    if not safe_path:
        console.print("[danger]Error: refusing to write outside the current directory[/danger]")
        return
    try:
        file_path = Path(safe_path)
        file_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"[ok]→ Saved:[/ok] [url]{escape(file_path.name)}[/url]")
    except (OSError, ValueError) as exc:
        console.print(f"[danger]Error: {escape(str(exc))}[/danger]")


def _rescan_result(
    result: DomainResult,
    target: str,
    check_http: bool,
    console: Console,
    options: ScanOptions | None = None,
) -> DomainResult:
    """Re-runs a network check for a single variant and returns the updated scored result.

    *options* are the original scan's: re-probing one row of a ``--no-whois``
    or ``--no-dnsbl`` scan must not query a registry or a blocklist the
    operator chose to leave alone.
    """
    opts = options or ScanOptions()
    perm = Permutation(domain=result.domain, kind=result.kind, note=result.note)
    console.print(f"[muted]Rescanning {escape(result.domain)}…[/muted]")

    resolver_cls = _get_inter("Resolver", Resolver)

    async def _run() -> tuple[DomainResult, str | None]:
        async with resolver_cls(
            check_http=check_http,
            target=target,
            check_whois=opts.whois,
            check_dnsbl=opts.dnsbl,
        ) as resolver:
            res = await resolver.check_one(perm)
            return res, resolver.target_title

    raw, target_title = run_async(_run())
    scoring_mod = _get_inter("scoring", scoring)
    return cast(DomainResult, scoring_mod.score(raw, target, target_title=target_title))


def _suggest_defensive_whitelist(report: ScanReport, console: Console) -> None:
    """Offers to append detected defensive domains to whitelist.txt."""
    defensive = [r for r in report.registered if r.is_likely_defensive]
    if not defensive:
        return
    console.print(
        f"[warn]{GLYPH_DEFENSIVE}  {len(defensive)} domain(s) appear defensive "
        f"(redirect → original). Add to whitelist?[/warn]"
    )
    confirm_fn = _get_inter("_confirm", _confirm)
    if confirm_fn("Write to whitelist.txt?") is not True:
        return
    path = Path("whitelist.txt")
    try:
        with path.open("a+", encoding="utf-8") as f:
            f.seek(0)
            content = f.read()
            existing = parse_domain_list(content)
            new_entries = [
                r.domain for r in defensive if normalize_domain(r.domain) not in existing
            ]
            if new_entries:
                if content and not content.endswith(("\n", "\r")):
                    f.write("\n")
                for d in new_entries:
                    f.write(d + "\n")
        if new_entries:
            console.print(f"[ok]→ Added {len(new_entries)} domain(s) to {escape(str(path))}[/ok]")
        else:
            console.print("[muted]All already in whitelist.[/muted]")
    except OSError as exc:
        console.print(f"[danger]Error updating whitelist: {escape(str(exc))}[/danger]")


class _ActionResult:
    CONTINUE = "continue"
    NEXT_DOMAIN = "next_domain"
    QUIT = "quit"


class _ActionContext:
    __slots__ = (
        "check_http",
        "console",
        "report",
        "selected",
        "session_allowed",
        "target",
    )

    def __init__(
        self,
        selected: DomainResult,
        target: str,
        check_http: bool,
        report: ScanReport,
        session_allowed: set[str],
        console: Console,
    ) -> None:
        self.selected = selected
        self.target = target
        self.check_http = check_http
        self.report = report
        self.session_allowed = session_allowed
        self.console = console


def _handle_open(ctx: _ActionContext) -> str:
    url = f"https://{ctx.selected.domain}"
    defanged = ctx.selected.domain.replace(".", "[.]")
    ctx.console.print(
        f"[warn]⚠  OPSEC Warning: {escape(ctx.selected.domain)} is a suspicious domain "
        f"(risk: {ctx.selected.risk_level.value}). Opening in your browser may expose "
        f"you to fingerprinting, tracking, or malicious content.[/warn]"
    )
    ctx.console.print(f"[muted]Safe defanged IOC:[/muted] [value]hxxps://{defanged}[/value]")
    ctx.console.print(
        f"[muted]Sandbox lookup:[/muted] [url]https://urlscan.io/search/#{quote(ctx.selected.domain)}[/url]"
    )
    confirm_fn = _get_inter("_confirm", _confirm)
    if confirm_fn("Open anyway?") is not True:
        return _ActionResult.CONTINUE
    wb_mod = _get_inter("webbrowser", webbrowser)
    wb_mod.open(url)
    ctx.console.print(f"[ok]→ Opened[/ok] [url]{url}[/url]")
    return _ActionResult.CONTINUE


def _handle_whois(ctx: _ActionContext) -> str:
    show_whois_fn = _get_inter("_show_whois", _show_whois)
    show_whois_fn(ctx.selected, ctx.console)
    return _ActionResult.CONTINUE


def _handle_export(ctx: _ActionContext) -> str:
    export_fn = _get_inter("_export_result", _export_result)
    export_fn(ctx.selected, ctx.console)
    return _ActionResult.CONTINUE


def _handle_allow(ctx: _ActionContext) -> str:
    ctx.session_allowed.add(ctx.selected.domain)
    ctx.console.print(f"[ok]✓ {escape(ctx.selected.domain)} added to session whitelist[/ok]")
    return _ActionResult.NEXT_DOMAIN


def _handle_rescan(ctx: _ActionContext) -> str:
    rescan_fn = _get_inter("_rescan_result", _rescan_result)
    updated = rescan_fn(ctx.selected, ctx.target, ctx.check_http, ctx.console, ctx.report.options)
    for i, r in enumerate(ctx.report.results):
        if r.domain == ctx.selected.domain:
            ctx.report.results[i] = updated
            break
    ctx.selected = updated
    reporters_mod = _get_inter("reporters", reporters)
    reporters_mod.render_table(
        ScanReport(target=ctx.target, total_permutations=1, results=[updated]),
        ctx.console,
        show_safe=True,
    )
    return _ActionResult.NEXT_DOMAIN if not updated.is_registered else _ActionResult.CONTINUE


def _handle_takedown(ctx: _ActionContext) -> str:
    r = ctx.selected
    report_text = build_takedown_notice(r, ctx.target)
    ctx.console.print(
        Panel(Text(report_text), title="[brand]Abuse Takedown Notice[/brand]", border_style="brand")
    )

    q_mod = _get_inter("questionary", questionary)
    action = q_mod.select(
        "Takedown report options:",
        choices=[
            q_mod.Choice("Save to takedown file", value="save"),
            q_mod.Choice("Return to action menu", value="back"),
        ],
    ).ask()
    if action == "save":
        default_name = f"takedown-{r.domain.replace('.', '_')}.txt"
        fname = q_mod.text("Filename:", default=default_name).ask()
        if fname:
            safe_path = safe_relative_path(fname)
            if safe_path:
                try:
                    Path(safe_path).write_text(report_text, encoding="utf-8")
                    ctx.console.print(f"[ok]✓ Saved takedown request to {safe_path}[/ok]")
                except OSError as exc:
                    ctx.console.print(f"[danger]Error saving file: {escape(str(exc))}[/danger]")
            else:
                ctx.console.print("[danger]Error: unsafe filename[/danger]")

    return _ActionResult.CONTINUE


_ACTION_HANDLERS = {
    "open": _handle_open,
    "whois": _handle_whois,
    "export": _handle_export,
    "allow": _handle_allow,
    "rescan": _handle_rescan,
    "takedown": _handle_takedown,
}

_ACTION_CHOICES = [
    questionary.Choice("[o]pen     — open in browser", value="open"),
    questionary.Choice("[w]hois    — show registration info", value="whois"),
    questionary.Choice("[t]akedown — generate abuse/takedown report", value="takedown"),
    questionary.Choice("[e]xport   — save result as JSON", value="export"),
    questionary.Choice("[a]llow    — skip in this session", value="allow"),
    questionary.Choice("[r]escan   — re-check this domain now", value="rescan"),
    questionary.Choice("[b]ack     — pick a different domain", value="back"),
    questionary.Choice("[q]uit     — exit actions", value="quit"),
]

__all__ = [
    "_ACTION_CHOICES",
    "_ACTION_HANDLERS",
    "_ActionContext",
    "_ActionResult",
    "_export_result",
    "_handle_allow",
    "_handle_export",
    "_handle_open",
    "_handle_rescan",
    "_handle_takedown",
    "_handle_whois",
    "_rescan_result",
    "_show_whois",
    "_suggest_defensive_whitelist",
]
