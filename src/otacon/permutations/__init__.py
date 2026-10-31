"""Domain permutation generation engine for typosquatting, homoglyphs, and combosquatting."""

from __future__ import annotations

from ..core.models import Permutation
from ..core.types import PermutationType
from .generator import generate
from .idn import idn_squats, to_ace
from .rules import (
    _ALT_TLDS,
    _AZERTY_ADJACENT,
    _COMMON_MULTI_TLDS,
    _HOMOGLYPHS,
    _KEYBOARD_LAYOUTS,
    _QWERTY_ADJACENT,
    _QWERTZ_ADJACENT,
    _SOUND_ALIASES,
    _SPOOF_SUFFIXES,
    rule_bitsquats,
    rule_combos,
    rule_homoglyphs,
    rule_hyphenation,
    rule_plurals,
    rule_soundsquats,
    rule_typos,
    rule_vowel_swaps,
    rule_www_merge,
    split_domain,
)

# Compatibility aliases
_split_domain = split_domain

__all__ = [
    "_ALT_TLDS",
    "_AZERTY_ADJACENT",
    "_COMMON_MULTI_TLDS",
    "_HOMOGLYPHS",
    "_KEYBOARD_LAYOUTS",
    "_QWERTY_ADJACENT",
    "_QWERTZ_ADJACENT",
    "_SOUND_ALIASES",
    "_SPOOF_SUFFIXES",
    "Permutation",
    "PermutationType",
    "_split_domain",
    "generate",
    "idn_squats",
    "rule_bitsquats",
    "rule_combos",
    "rule_homoglyphs",
    "rule_hyphenation",
    "rule_plurals",
    "rule_soundsquats",
    "rule_typos",
    "rule_vowel_swaps",
    "rule_www_merge",
    "split_domain",
    "to_ace",
]
