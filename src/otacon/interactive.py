"""Interactive entry point — prompts for domain and options when otacon is run bare."""

from __future__ import annotations

import hashlib
import json
import logging
import webbrowser
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import httpx
import questionary
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.key_binding.key_processor import KeyPressEvent
from prompt_toolkit.shortcuts import prompt as _pt_prompt
from prompt_toolkit.validation import ValidationError, Validator
from rich import box
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__, enrich, permutations, reporters, scoring
from ._asyncutils import run_async
from ._scanner import run_scan
from ._validate import (
    is_valid_domain,
    normalize_domain,
    parse_domain_list,
    safe_relative_path,
)
from .models import DomainResult, Permutation, ScanReport
from .resolver import DEFAULT_CONCURRENCY, Resolver
from .theme import GLYPH_DEFENSIVE
from .whois import fetch_domain_age, format_age

_log = logging.getLogger("otacon.interactive")
_POINTER = "[*]"
_QMARK = "›"  # noqa: RUF001 — intentional UI glyph (single right-angle quote)


def _make_style(answer_color: str) -> questionary.Style:
    """Builds a questionary Style with the Otacon palette; ``answer_color`` varies per prompt."""
    return questionary.Style(
        [
            ("qmark", "fg:#00d7af bold"),
            ("question", "bold fg:#afafaf"),
            ("answer", f"fg:{answer_color}"),
            ("pointer", "fg:#00d7af bold"),
            ("highlighted", "fg:#00d7af bold"),
            ("selected", f"fg:{answer_color}"),
            ("instruction", "fg:#8a8a8a"),
            ("text", f"fg:{answer_color}"),
            ("disabled", "fg:#8a8a8a italic"),
            ("validator-toolbar", "bg:#870000 fg:#ffffff"),
        ]
    )


_STYLE = _make_style("#ffffff")
_STYLE_DOMAIN = _make_style("#5fd700")


class _YNValidator(Validator):
    """prompt_toolkit Validator that accepts y/n/empty and rejects everything else."""

    def validate(self, document: Document) -> None:
        """Raises ValidationError when the buffer holds anything other than y / n / empty."""
        if document.text.strip().lower() not in ("y", "n", ""):
            raise ValidationError(message="Type y or n", cursor_position=len(document.text))


def _yn_bindings() -> KeyBindings:
    """Key bindings that auto-submit on y/n without requiring Enter."""
    kb = KeyBindings()

    @kb.add("y")
    @kb.add("Y")
    def _yes(event: KeyPressEvent) -> None:
        event.app.current_buffer.text = "y"
        event.app.current_buffer.validate_and_handle()

    @kb.add("n")
    @kb.add("N")
    def _no(event: KeyPressEvent) -> None:
        event.app.current_buffer.text = "n"
        event.app.current_buffer.validate_and_handle()

    return kb


def _confirm(message: str) -> bool | None:
    """y/n prompt: green y, red n, auto-submits on keypress. Returns True/False/None (Ctrl+C)."""
    prompt_text = FormattedText(
        [
            ("fg:#00d7af bold", "› "),  # noqa: RUF001 — intentional UI glyph
            ("bold fg:#afafaf", f"{message} ("),
            ("fg:#5fd700 bold", "y"),
            ("fg:#8a8a8a", "/"),
            ("fg:#ff5f5f bold", "n"),
            ("fg:#8a8a8a", ") "),
        ]
    )
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
    """questionary validator: returns True for a valid FQDN, or an error string."""
    domain = normalize_domain(text)
    if not domain:
        return "Domain cannot be empty"
    if not is_valid_domain(domain):
        return "Invalid domain (expected format: example.com)"
    return True


def _validate_limit(text: str) -> bool | str:
    """questionary validator: returns True for a non-negative int, or an error string."""
    try:
        if int(text) < 0:
            return "Enter 0 or greater"
        return True
    except ValueError:
        return "Enter a number (0 = all)"


def run(console: Console) -> None:
    """Called by cli._main when otacon is invoked with no subcommand."""
    console.print(
        "[muted]Type the domain you want to protect. Otacon builds the lookalikes an "
        "attacker could register and checks which ones exist.[/muted]\n"
    )
    domain = questionary.text(
        "Your domain (e.g. example.com):",
        validate=_validate_domain,
        qmark=_QMARK,
        style=_STYLE_DOMAIN,
    ).ask()
    if domain is None:
        return
    domain = normalize_domain(domain)

    mode = questionary.select(
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
        _interactive_scan(domain, console)
    else:
        _interactive_generate(domain, console)


def _interactive_scan(domain: str, console: Console) -> None:
    """Guided scan: asks for network mode and show-all, then runs the resolver."""
    network = questionary.select(
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

    show_all = _confirm("Also list lookalikes nobody has registered?")
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

    report = run_async(
        _scan(
            domain,
            concurrency=DEFAULT_CONCURRENCY,
            check_http=check_http,
            console=console,
            exclude=exclusions or None,
        )
    )
    reporters.render_table(report, console, show_safe=show_all)
    _suggest_defensive_whitelist(report, console)
    _action_loop(report, domain, console, check_http=check_http)


def _interactive_generate(domain: str, console: Console) -> None:
    """Guided generate: asks for an optional display limit, prints the variant list."""
    limit_str = questionary.text(
        "Result limit (0 = all):",
        default="0",
        validate=_validate_limit,
        qmark=_QMARK,
        style=_STYLE,
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
        console.print(f"  [field]IPs:[/field]     [value]{escape(ips)}[/value]")
    if result.mx_records:
        mx = ", ".join(result.mx_records[:3])
        console.print(f"  [field]MX:[/field]      [value]{escape(mx)}[/value]")
    console.print()


def _export_result(result: DomainResult, console: Console) -> None:
    """Saves a single domain result as a JSON file under the current directory.

    The write is confined to the CWD: absolute paths and ``..`` escapes are
    rejected after canonicalisation, so a typo (or paste) can't clobber an
    arbitrary file like ``/etc/cron.d/x`` or a Windows startup folder.
    """
    default_name = f"{result.domain.replace('.', '_')}.json"
    filename = questionary.text(
        "Save as:",
        default=default_name,
        qmark=_QMARK,
        style=_STYLE,
    ).ask()
    if filename is None:
        return

    # safe_relative_path rejects absolute paths, `..` escapes, and Windows
    # reserved device names — same policy as the CLI report writers.
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
    result: DomainResult, target: str, check_http: bool, console: Console
) -> DomainResult:
    """Re-runs a network check for a single variant and returns the updated scored result."""
    perm = Permutation(domain=result.domain, kind=result.kind, note=result.note)
    console.print(f"[muted]Rescanning {escape(result.domain)}…[/muted]")

    async def _run() -> tuple[DomainResult, str | None, int | None]:
        async with Resolver(check_http=check_http, target=target) as resolver:
            res = await resolver.check_one(perm)
            return res, resolver.target_title, resolver.target_favicon

    raw, target_title, target_favicon = run_async(_run())
    return scoring.score(raw, target, target_title=target_title, target_favicon=target_favicon)


def _suggest_defensive_whitelist(report: ScanReport, console: Console) -> None:
    """After a scan, if defensive domains were found, offer to write them to whitelist.txt."""
    defensive = [r for r in report.registered if r.is_likely_defensive]
    if not defensive:
        return
    console.print(
        f"[warn]{GLYPH_DEFENSIVE}  {len(defensive)} domain(s) appear defensive "
        f"(redirect → original). Add to whitelist?[/warn]"
    )
    if _confirm("Write to whitelist.txt?") is not True:
        return
    path = Path("whitelist.txt")
    try:
        # One handle for both the read and the append, rather than a
        # read_text() followed by a separate open("a"): a second `otacon`
        # process writing to the same whitelist.txt between those two calls
        # could otherwise leave the "does the file already end in a newline"
        # check below stale, re-fusing entries under a race the same way a
        # hand-edited file without one does.
        with path.open("a+", encoding="utf-8") as f:
            f.seek(0)
            # Read back through the same parser the whitelist is loaded with,
            # so an entry written by an earlier run is recognised even if the
            # file picked up CRLF endings or the user hand-edited the casing.
            content = f.read()
            existing = parse_domain_list(content)
            new_entries = [
                r.domain for r in defensive if normalize_domain(r.domain) not in existing
            ]
            if new_entries:
                # A hand-edited file need not end in a newline; appending straight
                # onto it would fuse its last entry with the first new one.
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
    """Control-flow tokens returned by per-action handlers.

    ``CONTINUE`` keeps the action menu open for the same domain;
    ``NEXT_DOMAIN`` returns to the domain picker; ``QUIT`` exits the loop.
    """

    CONTINUE = "continue"
    NEXT_DOMAIN = "next_domain"
    QUIT = "quit"


class _ActionContext:
    """Mutable state shared across action handlers in a single _action_loop session."""

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
    """Safely handles opening or inspecting the lookalike domain."""
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
    if _confirm("Open anyway?") is not True:
        return _ActionResult.CONTINUE
    webbrowser.open(url)
    ctx.console.print(f"[ok]→ Opened[/ok] [url]{url}[/url]")
    return _ActionResult.CONTINUE


def _handle_whois(ctx: _ActionContext) -> str:
    """Shows WHOIS registration details for the selected domain."""
    _show_whois(ctx.selected, ctx.console)
    return _ActionResult.CONTINUE


def _handle_export(ctx: _ActionContext) -> str:
    """Writes the selected DomainResult to a JSON file inside CWD."""
    _export_result(ctx.selected, ctx.console)
    return _ActionResult.CONTINUE


def _handle_allow(ctx: _ActionContext) -> str:
    """Adds the selected domain to this session's allowlist and advances to the next domain."""
    ctx.session_allowed.add(ctx.selected.domain)
    ctx.console.print(f"[ok]✓ {escape(ctx.selected.domain)} added to session whitelist[/ok]")
    return _ActionResult.NEXT_DOMAIN


def _handle_rescan(ctx: _ActionContext) -> str:
    """Re-runs the resolver for the selected domain and updates the report in place."""
    updated = _rescan_result(ctx.selected, ctx.target, ctx.check_http, ctx.console)
    for i, r in enumerate(ctx.report.results):
        if r.domain == ctx.selected.domain:
            ctx.report.results[i] = updated
            break
    ctx.selected = updated
    reporters.render_table(
        ScanReport(target=ctx.target, total_permutations=1, results=[updated]),
        ctx.console,
        show_safe=True,
    )
    # Domain went offline mid-session — no point keeping the menu on a SAFE row.
    return _ActionResult.NEXT_DOMAIN if not updated.is_registered else _ActionResult.CONTINUE


def _evidence_pack(r: DomainResult, contacts: dict[str, str], notice: str) -> str:
    """JSON record of everything behind a takedown notice, for the case file.

    The SHA-256 ties the record to the exact notice text that was sent.
    """
    return json.dumps(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "tool": f"otacon {__version__}",
            "notice_sha256": hashlib.sha256(notice.encode("utf-8")).hexdigest(),
            "contacts": contacts,
            "result": r.model_dump(mode="json"),
        },
        indent=2,
    )


async def _takedown_contacts(r: DomainResult) -> dict[str, str]:
    """RDAP abuse contacts for *r*'s registrar and the network hosting its first IP."""
    async with httpx.AsyncClient() as client:
        ip = r.ip_addresses[0] if r.ip_addresses else None
        return await enrich.takedown_contacts(client, r.domain, ip)


def _handle_takedown(ctx: _ActionContext) -> str:
    """Generates an abuse takedown notice template with all collected evidence."""
    r = ctx.selected
    defanged = r.domain.replace(".", "[.]")
    now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    ips_str = ", ".join(r.ip_addresses) if r.ip_addresses else "N/A"
    mx_str = ", ".join(r.mx_records) if r.has_mx else "None detected"
    ssl_str = (
        f"Active (Issuer: {r.ssl_issuer or 'Unknown'}, Cert Age: {r.ssl_cert_age_days}d)"
        if r.has_ssl
        else "No active certificate"
    )
    http_str = (
        f'HTTP {r.http_status} (Title: "{r.page_title or "N/A"}")'
        if r.http_status is not None
        else "No HTTP response"
    )
    reasons_bullets = (
        "\n".join(f"  - {reason}" for reason in r.risk_reasons)
        if r.risk_reasons
        else "  - Suspicious domain impersonation"
    )
    hosting_str = (
        f"AS{r.asn} {r.as_name or ''} ({r.ip_country or '??'})" if r.asn is not None else "Unknown"
    )

    ctx.console.print("[muted]Looking up the registrar and hosting abuse contacts (RDAP)…[/muted]")
    contacts = run_async(_takedown_contacts(r))
    recipients = [contacts[k] for k in ("registrar_abuse", "hosting_abuse") if k in contacts]
    to_line = ", ".join(dict.fromkeys(recipients)) or "(no abuse contact in RDAP; check WHOIS)"

    report_text = f"""TO: {to_line}
SUBJECT: Urgent Abuse / Phishing Takedown Notice: {defanged}
TARGET BRAND: {ctx.target}
REGISTRAR: {contacts.get("registrar", "Unknown")}

DATE: {now_str}
MALICIOUS DOMAIN: {defanged} (raw: {r.domain})
IMPERSONATION TECHNIQUE: {r.kind.value}
RISK EVALUATION: {r.risk_score}/100 [{r.risk_level.value.upper()}]

INCIDENT EVIDENCE:
- Domain: {r.domain}
- IP Address(es): {ips_str}
- Hosting Network: {hosting_str}
- Mail Server(s) (MX): {mx_str}
- SSL/TLS Certificate: {ssl_str}
- Web Service: {http_str}
- Detected Risk Factors:
{reasons_bullets}

REQUESTED ACTION:
We request immediate suspension, de-registration, or null-routing of domain '{r.domain}'
to prevent unauthorized brand impersonation, fraudulent communications, and credential theft
targeting {ctx.target} users and customers.
"""
    ctx.console.print(
        # Text, not str: the notice embeds attacker-controlled strings (page
        # title, cert issuer, MX hosts) that Rich would otherwise parse as markup.
        Panel(Text(report_text), title="[brand]Abuse Takedown Notice[/brand]", border_style="brand")
    )

    action = questionary.select(
        "Takedown report options:",
        choices=[
            questionary.Choice("Save to takedown file", value="save"),
            questionary.Choice("Return to action menu", value="back"),
        ],
    ).ask()
    if action == "save":
        default_name = f"takedown-{r.domain.replace('.', '_')}.txt"
        fname = questionary.text("Filename:", default=default_name).ask()
        if fname:
            safe_path = safe_relative_path(fname)
            if safe_path:
                try:
                    notice = Path(safe_path)
                    # newline="": the bytes on disk must hash to notice_sha256 on Windows too.
                    notice.write_text(report_text, encoding="utf-8", newline="")
                    evidence = notice.with_name(notice.stem + ".evidence.json")
                    evidence.write_text(_evidence_pack(r, contacts, report_text), encoding="utf-8")
                    ctx.console.print(
                        f"[ok]✓ Saved takedown request to {escape(safe_path)}"
                        f" and its evidence to {escape(evidence.name)}[/ok]"
                    )
                except OSError as exc:
                    ctx.console.print(f"[danger]Error saving file: {escape(str(exc))}[/danger]")
            else:
                ctx.console.print("[danger]Error: unsafe filename[/danger]")

    return _ActionResult.CONTINUE


# Dispatch table for the post-scan action menu. Each handler returns one of the
# _ActionResult tokens; "back" and "quit" are control-only and stay inline.
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


def _evidence(r: DomainResult) -> list[tuple[str, str, str]]:
    """(label, fact, what it means) rows for the dossier, plain words first."""
    rows: list[tuple[str, str, str]] = []
    if r.resolves:
        rows.append(("Online", ", ".join(r.ip_addresses[:3]), "points to a live server"))
    if r.has_mx:
        rows.append(
            ("Mail", ", ".join(r.mx_records[:2]), "can send email that looks like it is from you")
        )
    if r.redirects_to:
        meaning = (
            "sends visitors to your own site, likely yours"
            if r.is_likely_defensive
            else "sends visitors somewhere else"
        )
        rows.append(("Redirect", r.redirects_to, meaning))
    elif r.http_status is not None:
        title = f'"{r.page_title}"' if r.page_title else f"HTTP {r.http_status}"
        meaning = "a page is up"
        if r.title_similarity is not None and r.title_similarity >= 0.8:
            meaning = "its page title copies yours"
        rows.append(("Website", title, meaning))
    if r.has_ssl:
        age = f", {r.ssl_cert_age_days} days old" if r.ssl_cert_age_days is not None else ""
        rows.append(
            ("Certificate", f"{r.ssl_issuer or 'unknown issuer'}{age}", "browsers show a padlock")
        )
    if r.age_days is not None:
        rows.append(("Registered", format_age(r.age_days) + " ago", "domain age from WHOIS/RDAP"))
    if r.is_parked:
        rows.append(("Parked", "placeholder page", "not in use yet, keep an eye on it"))
    return rows


def _dossier(r: DomainResult) -> Panel:
    """One card with everything known about *r*, explained for non-specialists.

    Every value is appended as Text, never parsed as markup: titles, issuers
    and MX hosts come straight from the lookalike's own servers.
    """
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="field", no_wrap=True)
    grid.add_column(style="value", overflow="fold")
    grid.add_column(style="muted")
    for label, fact, meaning in _evidence(r):
        grid.add_row(label, Text(fact), meaning)

    head = Text()
    head.append(f"{r.risk_level.icon} {r.risk_level.value.upper()} ", style=r.risk_level.style)
    head.append(f"{r.risk_score}/100", style="value")
    head.append(f"   {r.kind.value}", style="brand.dim")
    if r.note:
        head.append(f" · {r.note}", style="muted")
    parts: list[Text | Table] = [head, Text()]
    if grid.row_count:
        parts.append(grid)
    else:
        parts.append(Text("No network signals: registered, but nothing is running.", "muted"))
    return Panel(
        Group(*parts),
        title=Text(f" {r.domain} ", style="bold white"),
        title_align="left",
        border_style=r.risk_level.style,
        box=box.SQUARE,
        padding=(1, 2),
    )


def _pick_domain(report: ScanReport, session_allowed: set[str]) -> DomainResult | None:
    """Renders the domain picker and returns the chosen result (or None to exit)."""
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
    selected = questionary.select(
        "Pick a domain to inspect (riskiest first):",
        choices=choices,
        pointer=_POINTER,
        qmark=_QMARK,
        style=_STYLE,
    ).ask()
    return selected if isinstance(selected, DomainResult) else None


def _run_action_menu(ctx: _ActionContext) -> str:
    """Inner loop — keeps prompting for an action on ``ctx.selected`` until
    the handler signals NEXT_DOMAIN or QUIT."""
    ctx.console.print(_dossier(ctx.selected))
    while True:
        action = questionary.select(
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
    """Post-scan action loop — pick a registered domain row, then act on it.

    Outer loop drives the domain picker; inner loop (see _run_action_menu)
    drives the per-domain action menu via a handler-dispatch table.
    """
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
    """Runs the resolver and streams registered hits into a live progress table."""
    return await run_scan(
        domain,
        concurrency=concurrency,
        check_http=check_http,
        console=console,
        exclude=exclude,
    )
