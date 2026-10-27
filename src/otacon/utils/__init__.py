"""Shared utilities for validation and styling."""

from __future__ import annotations

from .theme import (
    BANNER,
    GLYPH_DEFENSIVE,
    GRADIENT,
    LOGO_DOTS_BOT,
    LOGO_DOTS_TOP,
    OTACON_THEME,
    SAFE_GLYPHS,
    SPOOF_INDEX,
    TAGLINE,
    WORDMARK,
    gradient,
    gradient_color,
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
    "GRADIENT",
    "LOGO_DOTS_BOT",
    "LOGO_DOTS_TOP",
    "OTACON_THEME",
    "SAFE_GLYPHS",
    "SPOOF_INDEX",
    "TAGLINE",
    "WORDMARK",
    "first_safe_ip",
    "gradient",
    "gradient_color",
    "is_valid_domain",
    "normalize_domain",
    "parse_domain_list",
    "parse_redirect",
    "safe_cli_path",
    "safe_relative_path",
]
