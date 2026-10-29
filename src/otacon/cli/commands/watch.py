"""CLI watch subcommand: the targets worth re-scanning, and how to automate it.

A lookalike registered this week matters more than one parked for years, which
is an argument for scanning on a schedule rather than when somebody remembers.
Otacon does not become a daemon to do that — the machine already has one. This
keeps the list and prints the crontab lines for it.
"""

from __future__ import annotations

import shutil
import sys

import typer
from rich.console import Console
from rich.markup import escape

from ... import config
from ...utils.validate import is_valid_domain, normalize_domain

# A fixed time would put every reader's scan on the same minute of the same
# hour, which is neither kind to the registries being queried nor useful.
_SCHEDULE = "17 7 * * *"


def _executable() -> str:
    """How to invoke Otacon from cron, where PATH is almost nothing.

    An absolute path, because a crontab that works in your shell and not in
    cron is the classic way to find out a week later that nothing ran.
    """
    found = shutil.which("otacon")
    return found or f"{sys.executable} -m otacon"


def execute_watch(
    console: Console,
    add: str | None,
    remove: str | None,
    schedule: str,
) -> None:
    """Lists the watchlist, or adds to it, or takes something off it."""
    if add and remove:
        console.print("[danger]Pass either --add or --remove, not both.[/danger]")
        raise typer.Exit(1)

    if not config.enabled():
        console.print(
            "[warn]OTACON_NO_CONFIG is set, so there is nowhere to keep a watchlist.[/warn]"
        )
        raise typer.Exit(1)

    for domain, watching in ((add, True), (remove, False)):
        if not domain:
            continue
        target = normalize_domain(domain)
        if not is_valid_domain(target):
            console.print(f"[danger]Error: invalid domain: {escape(domain)}[/danger]")
            raise typer.Exit(1)
        config.set_watched(target, watching)
        verb = "now watched" if watching else "no longer watched"
        console.print(f"[ok]{escape(target)}[/ok] [muted]{verb}[/muted]")

    targets = config.watched()
    if not targets:
        console.print(
            "[muted]Nothing on the watchlist. Add one with[/muted] "
            "[value]otacon watch --add example.com[/value][muted].[/muted]"
        )
        return

    console.print(f"\n[field]Watching {len(targets)} target(s)[/field]")
    for target in targets:
        allowed = len(config.target(target).allowed)
        line = f"  [value]{escape(target)}[/value]"
        if allowed:
            line += f"  [muted]{allowed} domain(s) left out[/muted]"
        console.print(line)

    binary = _executable()
    console.print("\n[field]Add these to your crontab[/field] [muted](crontab -e)[/muted]")
    for target in targets:
        # soft_wrap: a crontab entry has to survive being copied as one line.
        # Wrapped at the terminal's width it pastes as two, and the second half
        # becomes a schedule nobody wrote.
        console.print(
            f"  [muted]{escape(schedule)}[/muted] "
            f"[value]{escape(binary)} -q scan {escape(target)} "
            f"--json ~/otacon-{escape(target)}.json[/value]",
            soft_wrap=True,
        )
    console.print(
        "\n[muted]Add[/muted] [value]--fail-on high[/value][muted] to have cron mail you "
        "only when something dangerous turns up.[/muted]\n"
    )


__all__ = ["execute_watch"]
