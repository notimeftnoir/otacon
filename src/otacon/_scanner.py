"""The shared scan loop — the single place that drives the resolver over a variant set.

Every entry point needs the same pipeline: generate permutations, check them
concurrently, score each result and collect the registered ones into a report.
The only thing that actually differs between callers is whether a live progress
view is drawn, so that is a flag here rather than a reason to keep separate
copies of the loop.
"""

from __future__ import annotations

import asyncio
import time
from collections import Counter
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

from . import permutations, reporters, scoring
from .models import DomainResult, Permutation, ScanReport
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


async def run_scan(
    target: str,
    concurrency: int,
    check_http: bool,
    console: Console,
    exclude: set[str] | None = None,
    weights: scoring.ScoringWeights | None = None,
    show_progress: bool = True,
    check_whois: bool = True,
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
            )
        )

        for coro in asyncio.as_completed([resolver.check_one(p) for p in perms]):
            result = await coro
            scored = scoring.score(result, target, weights, resolver.target_title)
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
    return report
