"""Legacy import path for the theme — canonical home is :mod:`otacon.utils.theme`.

Kept because the pre-2.0 modules (``_splash``, ``diff``, ``interactive``) and a
number of tests import from here. This file held a byte-for-byte second copy of
the palette until the v2.0 cleanup, which meant a re-theme had to be applied
twice to take effect everywhere.
"""

from __future__ import annotations

from .core.types import RiskLevel
from .utils.theme import (
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
    "RiskLevel",
    "gradient",
    "gradient_color",
]
