"""Compatibility shim for interactive mode in otacon v2.0."""

from __future__ import annotations

import webbrowser

import questionary
from prompt_toolkit.shortcuts import prompt as _pt_prompt

from . import permutations, reporters, scoring
from ._asyncutils import run_async
from ._scanner import run_scan
from ._validate import (
    is_valid_domain,
    normalize_domain,
    parse_domain_list,
    safe_relative_path,
)
from .models import DomainResult, Permutation, ScanReport
from .net.whois import fetch_domain_age, format_age
from .resolver import DEFAULT_CONCURRENCY, Resolver
from .theme import GLYPH_DEFENSIVE, RiskLevel
from .triage.actions import (
    _ACTION_CHOICES,
    _ACTION_HANDLERS,
    _ActionContext,
    _ActionResult,
    _export_result,
    _handle_allow,
    _handle_export,
    _handle_open,
    _handle_rescan,
    _handle_takedown,
    _handle_whois,
    _rescan_result,
    _show_whois,
    _suggest_defensive_whitelist,
)
from .triage.dossier import _dossier
from .triage.prompts import (
    _POINTER,
    _QMARK,
    _STYLE,
    _STYLE_DOMAIN,
    _confirm,
    _make_style,
    _validate_domain,
    _validate_limit,
    _yn_bindings,
    _YNValidator,
)
from .triage.workflow import (
    _action_loop,
    _interactive_generate,
    _interactive_scan,
    _pick_domain,
    _run_action_menu,
    _scan,
    run,
)

__all__ = [
    "DEFAULT_CONCURRENCY",
    "GLYPH_DEFENSIVE",
    "_ACTION_CHOICES",
    "_ACTION_HANDLERS",
    "_POINTER",
    "_QMARK",
    "_STYLE",
    "_STYLE_DOMAIN",
    "DomainResult",
    "Permutation",
    "Resolver",
    "RiskLevel",
    "ScanReport",
    "_ActionContext",
    "_ActionResult",
    "_YNValidator",
    "_action_loop",
    "_confirm",
    "_dossier",
    "_export_result",
    "_handle_allow",
    "_handle_export",
    "_handle_open",
    "_handle_rescan",
    "_handle_takedown",
    "_handle_whois",
    "_interactive_generate",
    "_interactive_scan",
    "_make_style",
    "_pick_domain",
    "_pt_prompt",
    "_rescan_result",
    "_run_action_menu",
    "_scan",
    "_show_whois",
    "_suggest_defensive_whitelist",
    "_validate_domain",
    "_validate_limit",
    "_yn_bindings",
    "fetch_domain_age",
    "format_age",
    "is_valid_domain",
    "normalize_domain",
    "parse_domain_list",
    "permutations",
    "questionary",
    "reporters",
    "run",
    "run_async",
    "run_scan",
    "safe_relative_path",
    "scoring",
    "webbrowser",
]
