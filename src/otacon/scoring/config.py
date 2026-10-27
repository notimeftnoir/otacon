"""Scoring weights configuration for risk calculations."""

from __future__ import annotations

import logging
from typing import Any

from ..core.types import PermutationType

_log = logging.getLogger("otacon.scoring.config")


class ScoringWeights:
    """Configurable scoring weights for risk calculation."""

    def __init__(self, overrides: dict[str, Any] | None = None) -> None:
        if overrides is not None and not isinstance(overrides, dict):
            raise TypeError("overrides must be a dict")

        self.points_resolves = 10
        self.points_http_2xx = 15
        self.points_http_3xx = 10
        self.points_http_4xx = 5
        self.points_http_5xx = 3
        self.points_mx = 25
        self.points_ssl = 15
        self.points_ssl_fresh = 10
        self.points_ssl_san_mismatch = 5
        self.points_redirect = 5
        self.points_age_fresh = 20
        self.points_age_new = 12
        self.points_age_recent = 5
        self.points_cloned_title = 25
        self.points_cloned_favicon = 35
        self.points_login_form = 20
        self.points_dnsbl = 50
        self.points_mail_spoofable = 15

        self.kind_base: dict[PermutationType, int] = {
            PermutationType.HOMOGLYPH: 25,
            PermutationType.IDN: 25,
            PermutationType.SUBDOMAIN: 22,
            PermutationType.WWW_MERGE: 20,
            PermutationType.COMBO: 20,
            PermutationType.CT_LOG: 20,
            PermutationType.TYPO: 18,
            PermutationType.SOUNDSQUAT: 16,
            PermutationType.BITSQUAT: 15,
            PermutationType.HYPHEN: 12,
            PermutationType.VOWEL_SWAP: 14,
            PermutationType.PLURAL: 10,
            PermutationType.TLD_SWAP: 10,
        }

        if overrides:
            self._apply_overrides(overrides)

    def _apply_overrides(self, overrides: dict[str, Any]) -> None:
        for k, v in overrides.items():
            if k == "kind_base" and isinstance(v, dict):
                for p_name, val in v.items():
                    try:
                        p_type = PermutationType(p_name)
                        self.kind_base[p_type] = int(val)
                    except (ValueError, TypeError):
                        _log.debug("ignoring kind_base override %r=%r", p_name, val)
            elif k == "kind_base":
                continue
            elif hasattr(self, k) and not k.startswith("_"):
                setattr(self, k, int(v))
            else:
                _log.debug("ignoring unknown scoring weight override %r=%r", k, v)


__all__ = ["ScoringWeights"]
