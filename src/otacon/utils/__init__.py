"""Shared utilities for validation and styling."""

from __future__ import annotations

from .theme import (
    BANNER,
    GLYPH_DEFENSIVE,
    HOMOGLYPH,
    LOGO_SWEEP,
    OTACON_THEME,
    SAFE_GLYPHS,
    SPOOF_INDEX,
    TAGLINE,
    WORDMARK,
    banner,
    wordmark_markup,
)
from .validate import (
    first_safe_ip,
    is_valid_domain,
    normalize_domain,
    parse_domain_list,
    parse_redirect,
    safe_cli_path,
    safe_relative_path,
)

__all__ = [
    "BANNER",
    "GLYPH_DEFENSIVE",
    "HOMOGLYPH",
    "LOGO_SWEEP",
    "OTACON_THEME",
    "SAFE_GLYPHS",
    "SPOOF_INDEX",
    "TAGLINE",
    "WORDMARK",
    "banner",
    "first_safe_ip",
    "is_valid_domain",
    "normalize_domain",
    "parse_domain_list",
    "parse_redirect",
    "safe_cli_path",
    "safe_relative_path",
    "wordmark_markup",
]
