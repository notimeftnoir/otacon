"""Compatibility shim for scan engine in otacon v2.0."""

from __future__ import annotations

from . import permutations
from .engine.scanner import (
    _HIJACK_WARNING,
    _LIVE_ROWS,
    _build_progress,
    _tally,
    _variant_summary,
    run_scan,
)
from .net.resolver import Resolver

__all__ = [
    "_HIJACK_WARNING",
    "_LIVE_ROWS",
    "Resolver",
    "_build_progress",
    "_tally",
    "_variant_summary",
    "permutations",
    "run_scan",
]
