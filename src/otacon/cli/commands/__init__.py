"""CLI subcommands."""

from __future__ import annotations

from .diff import execute_diff
from .generate import execute_generate
from .scan import execute_scan

__all__ = ["execute_diff", "execute_generate", "execute_scan"]
