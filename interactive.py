"""Interactive entry point — prompts for domain and options when otacon is run bare."""
from __future__ import annotations

import asyncio

import questionary
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from . import permutations, reporters, scoring
from .models import ScanReport
from .resolver import Resolver

_POINTER = "[*]"


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
    pass


def _interactive_scan(domain: str, console: Console) -> None:
    pass


def _interactive_generate(domain: str, console: Console) -> None:
    pass


async def _scan(domain: str, concurrency: int, check_http: bool, console: Console) -> ScanReport:
    pass  # type: ignore[return-value]
