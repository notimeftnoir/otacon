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
_typos = rule_typos
_homoglyphs = rule_homoglyphs
_combos = rule_combos
_bitsquats = rule_bitsquats
_hyphenation = rule_hyphenation
_soundsquats = rule_soundsquats
_vowel_swaps = rule_vowel_swaps
_plurals = rule_plurals
_www_merge = rule_www_merge
_to_ace = to_ace
_idn_squats = idn_squats

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
    "_bitsquats",
    "_combos",
    "_homoglyphs",
    "_hyphenation",
    "_idn_squats",
    "_plurals",
    "_soundsquats",
    "_split_domain",
    "_to_ace",
    "_typos",
    "_vowel_swaps",
    "_www_merge",
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
