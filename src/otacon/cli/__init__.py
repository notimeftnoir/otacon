"""Typer CLI entry point and subpackage for Otacon v2.0."""

from __future__ import annotations

import sys

from .. import permutations, scoring
from .commands.scan import (
    _load_domains,
    _load_exclusions,
    _load_weights,
    _run_scan,
)
from .main import (
    _configure_logging,
    _ensure_unicode_output,
    app,
    console,
)
from .state import _state

__all__ = [
    "_configure_logging",
    "_ensure_unicode_output",
    "_load_domains",
    "_load_exclusions",
    "_load_weights",
    "_run_scan",
    "_state",
    "app",
    "console",
    "permutations",
    "scoring",
    "sys",
]
