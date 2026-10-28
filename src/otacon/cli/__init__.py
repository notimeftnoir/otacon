"""Typer CLI entry point and subpackage for Otacon v2.0."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .. import permutations, reporters, scoring
from .._asyncutils import run_async
from .._splash import play_intro
from ..core.models import ScanReport
from ..core.types import RiskLevel
from ..engine.scanner import run_scan
from ..utils.theme import BANNER, OTACON_THEME
from ..utils.validate import (
    is_valid_domain,
    normalize_domain,
    parse_domain_list,
    safe_cli_path,
)
from .commands.diff import execute_diff
from .commands.generate import execute_generate
from .commands.scan import (
    _CI,
    _FILTER,
    _NET,
    _OUT,
    _load_domains,
    _load_exclusions,
    _load_weights,
    _print_next_steps,
    _run_scan,
    execute_scan,
)
from .main import (
    _banner,
    _configure_logging,
    _ensure_unicode_output,
    _Threshold,
    _version_callback,
    app,
    console,
    diff,
    generate,
    scan,
)
from .state import _CliState, _state

__all__ = [
    "BANNER",
    "OTACON_THEME",
    "_CI",
    "_FILTER",
    "_NET",
    "_OUT",
    "Enum",
    "Path",
    "RiskLevel",
    "ScanReport",
    "_CliState",
    "_Threshold",
    "_banner",
    "_configure_logging",
    "_ensure_unicode_output",
    "_load_domains",
    "_load_exclusions",
    "_load_weights",
    "_print_next_steps",
    "_run_scan",
    "_state",
    "_version_callback",
    "app",
    "console",
    "dataclass",
    "diff",
    "execute_diff",
    "execute_generate",
    "execute_scan",
    "generate",
    "is_valid_domain",
    "normalize_domain",
    "parse_domain_list",
    "permutations",
    "play_intro",
    "reporters",
    "run_async",
    "run_scan",
    "safe_cli_path",
    "scan",
    "scoring",
    "sys",
]
