"""Compatibility shim for permutation generator in otacon v2.0."""

from __future__ import annotations

from .core.models import Permutation
from .core.types import PermutationType
from .permutations.generator import generate
from .permutations.idn import idn_squats, to_ace
from .permutations.rules import (
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

# Backwards compatibility private aliases
_bitsquats = rule_bitsquats
_combos = rule_combos
_homoglyphs = rule_homoglyphs
_hyphenation = rule_hyphenation
_idn_squats = idn_squats
_plurals = rule_plurals
_soundsquats = rule_soundsquats
_split_domain = split_domain
_to_ace = to_ace
_typos = rule_typos
_vowel_swaps = rule_vowel_swaps
_www_merge = rule_www_merge

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
