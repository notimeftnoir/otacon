"""Legacy import path for the validators — canonical home is :mod:`otacon.utils.validate`.

Kept because ``ct_logs`` and ``interactive`` and several tests import from here.
This file held a second full copy of the domain and path validators until the
v2.0 cleanup; two divergent copies of a trust-boundary check is exactly the kind
of duplication that lets one of them fall behind.
"""

from __future__ import annotations

from .utils.validate import (
    _LABEL_RE,
    _WIN_RESERVED,
    first_safe_ip,
    is_valid_domain,
    normalize_domain,
    parse_domain_list,
    parse_redirect,
    safe_cli_path,
    safe_relative_path,
)

__all__ = [
    "_LABEL_RE",
    "_WIN_RESERVED",
    "first_safe_ip",
    "is_valid_domain",
    "normalize_domain",
    "parse_domain_list",
    "parse_redirect",
    "safe_cli_path",
    "safe_relative_path",
]
