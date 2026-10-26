"""The shared scan loop — the single place that drives the resolver over a variant set.

Every entry point needs the same pipeline: generate permutations, check them
concurrently, score each result and collect the registered ones into a report.
The only thing that actually differs between callers is whether a live progress
view is drawn, so that is a flag here rather than a reason to keep separate
copies of the loop.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import Counter
from contextlib import AsyncExitStack
from datetime import datetime

import httpx
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
)

from . import __version__, ct, intel, permutations, reporters, scoring
from .models import Discovery, DomainResult, Permutation, ScanReport
from .resolver import Resolver

_HIJACK_WARNING = (
    "[warn]⚠  Your DNS resolver answers nonexistent domains (NXDOMAIN hijacking)."
    " Hijacked answers were discarded; consider scanning with a clean resolver"
    " (e.g. 1.1.1.1).[/warn]"
)


# Live-table rows kept on screen while scanning: a table taller than the
# terminal makes Live redraw from the scrollback and flicker.
_LIVE_ROWS = 8


def _build_progress(console: Console) -> Progress:
    """Scan progress: pulsing spinner, bar, counter, running tally, time left."""
    spinner = SpinnerColumn(style="brand", finished_text="[ok]✓[/ok]")
    # Rich's default spinner is Braille, which conhost fonts lack; pulse the
    # risk density ramp instead (see theme.SAFE_GLYPHS).
    spinner.spinner.frames = list("░▒▓█▓▒")
    return Progress(
        spinner,
        TextColumn("[field]{task.description}"),
        BarColumn(complete_style="brand", finished_style="ok", pulse_style="brand.dim"),
        TextColumn("[value]{task.completed}[/value][muted]/{task.total}[/muted]"),
        TextColumn("{task.fields[tally]}"),
        TimeRemainingColumn(compact=True, elapsed_when_finished=True),
        console=console,
    )


def _tally(hits: list[DomainResult]) -> str:
    """Markup for the running count of registered and dangerous lookalikes."""
    if not hits:
        return "[muted]nothing registered yet[/muted]"
    danger = sum(1 for h in hits if h.risk_level.rank >= 3)
    out = f"[warn]{len(hits)} registered[/warn]"
    return out + (f" [muted]·[/muted] [danger]{danger} dangerous[/danger]" if danger else "")


def _variant_summary(perms: list[Permutation]) -> str:
    """'412 lookalikes generated · typo 120 · homoglyph 80 …' as markup."""
    kinds = Counter(p.kind.value for p in perms).most_common(5)
    parts = " [muted]·[/muted] ".join(f"[muted]{k}[/muted] {n}" for k, n in kinds)
    return f"[ok]✓[/ok] [value]{len(perms)}[/value] lookalikes generated  {parts}"


# Longest the scan waits for crt.sh after its own work is done.
_CT_WAIT = 90.0


def _is_allowed(host: str, allowed: set[str]) -> bool:
    """True when *host* is a whitelisted domain or a subdomain of one."""
    labels = host.split(".")
    return any(".".join(labels[i:]) in allowed for i in range(len(labels) - 1))


def _examples(found: list[Discovery], n: int = 3) -> str:
    return escape(", ".join(d.host for d in found[:n]))


def _dmarc_advice(target: str, policy: str | None) -> str:
    """Plain-language warning for a target that does not enforce DMARC."""
    if policy is None:
        return (
            f"{escape(target)} publishes no DMARC policy: anyone can send email claiming to be"
            " from it, and many inboxes will accept it. Publish a DMARC record, starting with"
            " p=quarantine."
        )
    return (
        f"{escape(target)} has DMARC set to p=none (monitoring only): email spoofing it is still"
        " delivered. Move to p=quarantine, then p=reject."
    )


async def run_scan(
    target: str,
    concurrency: int,
    check_http: bool,
    console: Console,
    exclude: set[str] | None = None,
    weights: scoring.ScoringWeights | None = None,
    show_progress: bool = True,
    check_whois: bool = True,
    nameservers: list[str] | None = None,
    check_intel: bool = True,
) -> ScanReport:
    """Scans every permutation of *target* and returns the scored report.

    With *show_progress* the run streams registered hits into a live table above
    a progress bar; without it the identical loop runs silently — which is what
    ``--quiet`` needs, since there stdout is reserved for the JSON report.
    """
    perms = permutations.generate(target, exclude=exclude)
    report = ScanReport(target=target, total_permutations=len(perms))
    if not perms:
        return report

    hits: list[DomainResult] = []
    progress = _build_progress(console) if show_progress else None
    if progress is not None:
        console.print(_variant_summary(perms))
    started = time.monotonic()

    async with AsyncExitStack() as stack:
        live: Live | None = None
        task_id: TaskID | None = None
        if progress is not None:
            task_id = progress.add_task("Checking", total=len(perms), tally=_tally(hits))
            live = stack.enter_context(
                Live(progress, console=console, refresh_per_second=4, transient=True)
            )
        # Entered after Live so the spinner already covers the resolver's own
        # start-up work (it fetches the target's page title on entry).
        resolver = await stack.enter_async_context(
            Resolver(
                concurrency=concurrency,
                check_http=check_http,
                target=target,
                check_whois=check_whois,
                nameservers=nameservers,
            )
        )

        report.target_spf, report.target_dmarc = await resolver.mail_posture(target)

        # Feeds are matched locally against every variant up front; only the
        # opt-in URLhaus lookup sends names out, and only for registered ones.
        listed: dict[str, list[str]] = {}
        discovered: dict[str, Discovery] = {}
        perm_domains = {p.domain for p in perms}
        intel_client: httpx.AsyncClient | None = None
        ct_task: asyncio.Task[dict[str, datetime] | None] | None = None
        urlhaus_key = os.environ.get(intel.URLHAUS_KEY_ENV) if check_intel else None
        if check_intel:
            intel_client = await stack.enter_async_context(
                httpx.AsyncClient(timeout=20.0, headers={"User-Agent": f"Otacon/{__version__}"})
            )
            brand = permutations.brand_label(target)
            # CT runs alongside the scan: crt.sh can take a minute, the scan should not.
            ct_task = asyncio.create_task(ct.recent_certificates(intel_client, brand, target))
            stack.callback(ct_task.cancel)  # no-op once done; stops it if the scan fails
            feeds = await intel.load_feeds(intel_client)
            listed = intel.match(perm_domains, feeds)
            discovered = {
                host: Discovery(host=host, sources=sources)
                for host, sources in intel.mentions(brand, feeds, target).items()
                if host not in perm_domains
            }

        for coro in asyncio.as_completed([resolver.check_one(p) for p in perms]):
            result = await coro
            result.intel_sources = listed.get(result.domain, [])
            if (
                urlhaus_key
                and intel_client is not None
                and result.is_registered
                and await intel.urlhaus_listed(intel_client, result.domain, urlhaus_key)
            ):
                result.intel_sources = [*result.intel_sources, "URLhaus"]
            scored = scoring.score(
                result, target, weights, resolver.target_title, resolver.target_favicon
            )
            report.results.append(scored)
            if scored.is_registered:
                hits.append(scored)
                if live is not None and progress is not None:
                    live.update(
                        Group(progress, reporters.build_live_table(hits, target, _LIVE_ROWS))
                    )
            if progress is not None and task_id is not None:
                progress.update(task_id, advance=1, tally=_tally(hits))

        report.dns_hijack_detected = resolver.dns_hijack_detected

        if ct_task is not None:
            try:
                certs = await asyncio.wait_for(ct_task, _CT_WAIT)
            except TimeoutError:
                certs = None
            report.ct_available = certs is not None
            for host, issued in (certs or {}).items():
                if host not in perm_domains:
                    found = discovered.setdefault(host, Discovery(host=host))
                    found.sources.append("CT")
                    found.first_seen = issued
        # The whitelist covers the brand's other domains (allegrogroup.com) and
        # all their subdomains, which CT and feeds otherwise keep surfacing.
        allowed = {e.lower() for e in exclude or ()}
        report.discovered = sorted(
            (d for d in discovered.values() if not _is_allowed(d.host, allowed)),
            key=lambda d: d.host,
        )

    # Sort results deterministically: registered threats first (descending by score),
    # then alphabetically by domain. Ensures reproducible JSON reports and CI diffs.
    report.results.sort(key=lambda r: (-r.risk_score, r.domain))

    if progress is not None:
        console.print(
            f"[ok]✓[/ok] [value]{len(perms)}[/value] checked in "
            f"[value]{time.monotonic() - started:.1f}s[/value]  [muted]·[/muted] {_tally(hits)}"
        )
    if report.dns_hijack_detected:
        console.print(_HIJACK_WARNING)
    if report.target_dmarc in (None, "none"):
        console.print(f"[warn]⚠  {_dmarc_advice(target, report.target_dmarc)}[/warn]")
    reported = [d for d in report.discovered if any(s != "CT" for s in d.sources)]
    if reported:
        console.print(
            f"[danger]⚠  {len(reported)} host(s) already reported as phishing carry this brand"
            f" in their name[/danger] [muted](e.g. {_examples(reported)};"
            " full list in the --json report)[/muted]"
        )
    certified = [d for d in report.discovered if "CT" in d.sources]
    if certified:
        console.print(
            f"[warn]→  {len(certified)} new certificate name(s) in the last {ct.WINDOW_DAYS} days"
            f" carry this brand[/warn] [muted](crt.sh; e.g. {_examples(certified)})[/muted]"
        )
    if report.ct_available is False:
        console.print(
            "[muted]Certificate Transparency (crt.sh) was unreachable; new-certificate checks"
            " were skipped. Re-run later.[/muted]"
        )
    if report.inconclusive:
        console.print(
            f"[warn]⚠  {len(report.inconclusive)} variant(s) got no DNS answer even after"
            " retries, so whether they are registered is unknown. Your DNS server is"
            " likely dropping queries: re-run with --resolver 1.1.1.1.[/warn]"
        )
    return report
