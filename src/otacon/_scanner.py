"""The shared scan loop — the single place that drives the resolver over a variant set.

Every entry point needs the same pipeline: generate permutations, check them
concurrently, score each result and collect the registered ones into a report.
The only thing that actually differs between callers is whether a live progress
view is drawn, so that is a flag here rather than a reason to keep separate
copies of the loop.
"""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack

from rich.console import Console, Group
from rich.live import Live
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)

from . import permutations, reporters, scoring
from .models import DomainResult, ScanReport
from .resolver import Resolver

_HIJACK_WARNING = (
    "[warn]⚠  Your DNS resolver answers nonexistent domains (NXDOMAIN hijacking)."
    " Hijacked answers were discarded; consider scanning with a clean resolver"
    " (e.g. 1.1.1.1).[/warn]"
)


def _build_progress(console: Console) -> Progress:
    """Builds the scan progress bar: spinner, label, bar, counter, elapsed time."""
    return Progress(
        SpinnerColumn(style="brand"),
        TextColumn("[field]{task.description}"),
        BarColumn(complete_style="brand", finished_style="ok"),
        TextColumn("[muted]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    )


async def run_scan(
    target: str,
    concurrency: int,
    check_http: bool,
    console: Console,
    exclude: set[str] | None = None,
    weights: scoring.ScoringWeights | None = None,
    show_progress: bool = True,
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

    async with AsyncExitStack() as stack:
        live: Live | None = None
        task_id: TaskID | None = None
        if progress is not None:
            task_id = progress.add_task("Checking variants", total=len(perms))
            live = stack.enter_context(
                Live(progress, console=console, refresh_per_second=4, transient=True)
            )
        # Entered after Live so the spinner already covers the resolver's own
        # start-up work (it fetches the target's page title on entry).
        resolver = await stack.enter_async_context(
            Resolver(concurrency=concurrency, check_http=check_http, target=target)
        )

        for coro in asyncio.as_completed([resolver.check_one(p) for p in perms]):
            result = await coro
            scored = scoring.score(result, target, weights, resolver.target_title)
            report.results.append(scored)
            if progress is not None and task_id is not None:
                progress.advance(task_id)
            if scored.is_registered:
                hits.append(scored)
                if live is not None and progress is not None:
                    live.update(Group(progress, reporters.build_live_table(hits, target)))

        report.dns_hijack_detected = resolver.dns_hijack_detected

    if report.dns_hijack_detected:
        console.print(_HIJACK_WARNING)
    return report
