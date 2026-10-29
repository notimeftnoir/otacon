"""Asynchronous scan pipeline using structured concurrency with asyncio.TaskGroup."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter
from collections.abc import Callable
from contextlib import AsyncExitStack

from rich.console import Console, Group
from rich.live import Live
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
)

from .. import permutations
from ..core.models import DomainResult, Permutation, ScanOptions, ScanReport
from ..core.types import PermutationType, RiskLevel, ScanPhase
from ..net.resolver import Resolver
from ..reporters.console import build_live_table
from ..scoring.config import ScoringWeights
from ..scoring.engine import score
from .pool import ResourceLimiter
from .progress import ScanProgress

_log = logging.getLogger("otacon.engine.scanner")

_HIJACK_WARNING = (
    "[warn]⚠  Your DNS resolver answers nonexistent domains (NXDOMAIN hijacking)."
    " Hijacked answers were discarded; consider scanning with a clean resolver"
    " (e.g. 1.1.1.1).[/warn]"
)

_DNSBL_WARNING = (
    "[warn]⚠  A reputation list declined to answer, so DNSBL findings are"
    " incomplete. Large public resolvers are refused by Spamhaus; scan from a"
    " resolver of your own.[/warn]"
)

_LIVE_ROWS = 8


def _build_progress(console: Console) -> Progress:
    """Builds the Rich live scanning progress bar."""
    spinner = SpinnerColumn(style="brand", finished_text="[ok]✓[/ok]")
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
    """Running tally summary of registered and dangerous lookalike variants."""
    if not hits:
        return "[muted]nothing registered yet[/muted]"
    danger = sum(1 for h in hits if h.risk_level.rank >= 3)
    out = f"[warn]{len(hits)} registered[/warn]"
    return out + (f" [muted]·[/muted] [danger]{danger} dangerous[/danger]" if danger else "")


def _variant_summary(perms: list[Permutation]) -> str:
    """Breakdown of generated permutation techniques."""
    kinds = Counter(p.kind.value for p in perms).most_common(5)
    parts = " [muted]·[/muted] ".join(f"[muted]{k}[/muted] {n}" for k, n in kinds)
    return f"[ok]✓[/ok] [value]{len(perms)}[/value] lookalikes generated  {parts}"


async def run_scan(
    target: str,
    concurrency: int,
    check_http: bool,
    console: Console,
    exclude: set[str] | None = None,
    weights: ScoringWeights | None = None,
    show_progress: bool = True,
    check_whois: bool = True,
    check_dnsbl: bool = True,
    check_ct: bool = True,
    on_progress: Callable[[ScanProgress], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> ScanReport:
    """Scans all permutations of target using structured concurrency.

    ``on_progress`` is called with a :class:`ScanProgress` as the scan moves
    through its stages, and ``should_stop`` lets a front-end end it early: the
    remaining probes are skipped and the partial report comes back marked
    ``cancelled`` rather than the call raising, so what was found is kept.
    """
    results: list[DomainResult] = []
    hits: list[DomainResult] = []

    def report_progress(
        phase: ScanPhase, total: int = 0, latest: DomainResult | None = None
    ) -> None:
        if on_progress is None:
            return
        on_progress(
            ScanProgress(
                phase=phase,
                done=len(results),
                total=total,
                hits=len(hits),
                dangerous=sum(1 for h in hits if h.risk_level.rank >= RiskLevel.HIGH.rank),
                dns_queries=resolver_ref["r"].dns_queries if resolver_ref["r"] else 0,
                dns_failures=resolver_ref["r"].dns_failures if resolver_ref["r"] else 0,
                latest=latest,
            )
        )

    # The resolver does not exist until well after the first progress report,
    # and the DNS counters live on it.
    resolver_ref: dict[str, Resolver | None] = {"r": None}

    report_progress(ScanPhase.GENERATING)
    # The module is imported, not the function, so a test that patches
    # otacon.permutations.generate is seen here without any lookup.
    perms = await asyncio.to_thread(permutations.generate, target, exclude=exclude)
    if not perms:
        return ScanReport(target=target, total_permutations=0)

    safe_concurrency = ResourceLimiter.compute_safe_concurrency(concurrency)
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

        resolver = await stack.enter_async_context(
            Resolver(
                concurrency=safe_concurrency,
                check_http=check_http,
                target=target,
                check_whois=check_whois,
                check_dnsbl=check_dnsbl,
            )
        )

        resolver_ref["r"] = resolver
        report_progress(ScanPhase.CHECKING, total=len(perms))

        if check_ct:
            # A single slow network call that used to report nothing at all.
            report_progress(ScanPhase.DISCOVERING, total=len(perms))
            try:
                ct_domains = await resolver.fetch_ct_domains()
                existing = {p.domain for p in perms}
                # CT aggregators are queried with include_subdomains, so most hits are
                # the target's own infrastructure. Those are not impersonation — scoring
                # them as lookalikes made the target's own subdomains the single largest
                # source of critical findings.
                own_suffix = f".{target}"
                for d in sorted(ct_domains):
                    if d == target or d.endswith(own_suffix):
                        continue
                    if d not in existing and (exclude is None or d not in exclude):
                        perms.append(
                            Permutation(
                                domain=d,
                                kind=PermutationType.CT_LOG,
                                note="observed in Certificate Transparency logs",
                            )
                        )
                if progress is not None and task_id is not None:
                    progress.update(task_id, total=len(perms))
            except Exception as exc:
                _log.debug("CT log lookup failed: %r", exc)

        async with asyncio.TaskGroup() as tg:
            for perm in perms:

                async def _worker(p: Permutation = perm) -> None:
                    if should_stop is not None and should_stop():
                        # Returning rather than cancelling: the TaskGroup then
                        # unwinds normally and the caller keeps what was found.
                        return
                    raw_result = await resolver.check_one(p)
                    scored = score(raw_result, target, weights, resolver.target_title)
                    results.append(scored)
                    if scored.is_registered:
                        hits.append(scored)
                        if live is not None and progress is not None:
                            live.update(Group(progress, build_live_table(hits, target, _LIVE_ROWS)))
                    if progress is not None and task_id is not None:
                        progress.update(task_id, advance=1, tally=_tally(hits))
                    # Lets a non-Rich front-end (the TUI) show everything the
                    # console reporter draws for itself, the live hits included.
                    report_progress(
                        ScanPhase.CHECKING,
                        total=len(perms),
                        latest=scored if scored.is_registered else None,
                    )

                tg.create_task(_worker())

        hijack_detected = resolver.dns_hijack_detected
        dns_queries = resolver.dns_queries
        dns_failures = resolver.dns_failures
        probe_failures = resolver.probe_failures
        dnsbl_refused = resolver.dnsbl_refused

    results.sort(key=lambda r: (-r.risk_score, r.domain))
    report = ScanReport(
        target=target,
        total_permutations=len(perms),
        results=results,
        dns_hijack_detected=hijack_detected,
        dns_queries=dns_queries,
        dns_failures=dns_failures,
        probe_failures=probe_failures,
        dnsbl_refused=dnsbl_refused,
        options=ScanOptions(http=check_http, whois=check_whois, dnsbl=check_dnsbl, ct=check_ct),
        cancelled=should_stop is not None and should_stop(),
    )

    if progress is not None:
        console.print(
            f"[ok]✓[/ok] [value]{len(perms)}[/value] checked in "
            f"[value]{time.monotonic() - started:.1f}s[/value]  [muted]·[/muted] {_tally(hits)}"
        )
    if report.dns_hijack_detected:
        console.print(_HIJACK_WARNING)
    if dnsbl_refused:
        console.print(_DNSBL_WARNING)
    return report


__all__ = ["_LIVE_ROWS", "run_scan"]
