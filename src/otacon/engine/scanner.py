"""Asynchronous scan pipeline using structured concurrency with asyncio.TaskGroup."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter
from collections.abc import Callable
from contextlib import AsyncExitStack
from typing import Any

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

from ..core.models import DomainResult, Permutation, ScanReport
from ..core.types import PermutationType
from ..net.resolver import Resolver
from ..permutations.generator import generate
from ..reporters.console import build_live_table
from ..scoring.config import ScoringWeights
from ..scoring.engine import score
from .pool import ResourceLimiter

_log = logging.getLogger("otacon.engine.scanner")

_HIJACK_WARNING = (
    "[warn]⚠  Your DNS resolver answers nonexistent domains (NXDOMAIN hijacking)."
    " Hijacked answers were discarded; consider scanning with a clean resolver"
    " (e.g. 1.1.1.1).[/warn]"
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


def _get_generate_fn() -> Any:
    import sys

    for mod_name in ("otacon.interactive", "otacon.cli", "otacon._scanner"):
        mod = sys.modules.get(mod_name)
        if mod and hasattr(mod, "permutations") and hasattr(mod.permutations, "generate"):
            val = mod.permutations.generate
            if val is not generate:
                return val
    mod = sys.modules.get("otacon.permutations")
    if mod and hasattr(mod, "generate"):
        val = mod.generate
        if val is not generate:
            return val
    return generate


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
    on_progress: Callable[[int, int], None] | None = None,
) -> ScanReport:
    """Scans all permutations of target using structured concurrency."""
    gen_fn = _get_generate_fn()
    perms = await asyncio.to_thread(gen_fn, target, exclude=exclude)
    if not perms:
        return ScanReport(target=target, total_permutations=0)

    safe_concurrency = ResourceLimiter.compute_safe_concurrency(concurrency)
    results: list[DomainResult] = []
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

        resolver_cls = Resolver
        try:
            resolver = await stack.enter_async_context(
                resolver_cls(
                    concurrency=safe_concurrency,
                    check_http=check_http,
                    target=target,
                    check_whois=check_whois,
                    check_dnsbl=check_dnsbl,
                )
            )
        except TypeError:
            resolver = await stack.enter_async_context(
                resolver_cls(
                    concurrency=safe_concurrency,
                    check_http=check_http,
                    target=target,
                    check_whois=check_whois,
                )
            )

        if check_ct and hasattr(resolver, "fetch_ct_domains"):
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
                    raw_result = await resolver.check_one(p)
                    scored = score(raw_result, target, weights, resolver.target_title)
                    results.append(scored)
                    if scored.is_registered:
                        hits.append(scored)
                        if live is not None and progress is not None:
                            live.update(Group(progress, build_live_table(hits, target, _LIVE_ROWS)))
                    if progress is not None and task_id is not None:
                        progress.update(task_id, advance=1, tally=_tally(hits))
                    if on_progress is not None:
                        # Lets a non-Rich front-end (the TUI) show the same
                        # progress the console reporter draws for itself.
                        on_progress(len(results), len(perms))

                tg.create_task(_worker())

        hijack_detected = resolver.dns_hijack_detected
        # getattr: a test double standing in for Resolver need not carry counters.
        dns_queries = int(getattr(resolver, "dns_queries", 0))
        dns_failures = int(getattr(resolver, "dns_failures", 0))

    results.sort(key=lambda r: (-r.risk_score, r.domain))
    report = ScanReport(
        target=target,
        total_permutations=len(perms),
        results=results,
        dns_hijack_detected=hijack_detected,
        dns_queries=dns_queries,
        dns_failures=dns_failures,
    )

    if progress is not None:
        console.print(
            f"[ok]✓[/ok] [value]{len(perms)}[/value] checked in "
            f"[value]{time.monotonic() - started:.1f}s[/value]  [muted]·[/muted] {_tally(hits)}"
        )
    if report.dns_hijack_detected:
        console.print(_HIJACK_WARNING)
    return report


__all__ = ["_LIVE_ROWS", "run_scan"]
