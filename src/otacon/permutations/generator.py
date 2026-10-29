"""Permutation pipeline orchestrator generating and deduplicating lookalike domain variants."""

from __future__ import annotations

from ..core.models import Permutation
from ..core.types import PermutationType
from ..utils.validate import is_valid_domain, normalize_domain
from .idn import idn_squats, to_ace
from .rules import (
    _ALT_TLDS,
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


def generate(domain: str, exclude: set[str] | None = None) -> list[Permutation]:
    """Generates deduplicated domain permutations with technique attribution.

    Returns an empty list for anything that is not a domain. Both CLI callers
    already check that, but this is public API: given a bare label it used to
    return permutations of it with no TLD at all — "aa", "aq", "4" — which are
    not domains and which the scanner would have queried one by one.
    """
    cleaned = normalize_domain(domain)
    # Validate the ACE form, not the raw input: an IDN target is legitimate and
    # every variant is emitted as punycode anyway, but "bücher.de" has no
    # RFC 1035 label until it is encoded.
    base = to_ace(cleaned) or cleaned
    if not is_valid_domain(base):
        return []
    label, tld = split_domain(domain)
    if not label:
        return []

    seen: set[str] = {base}

    if exclude:
        for entry in exclude:
            cleaned = entry.lower().strip().rstrip(".")
            if not cleaned:
                continue
            seen.add(to_ace(cleaned) or cleaned)

    result: list[Permutation] = []
    homoglyph_variants = rule_homoglyphs(label)

    pipeline: list[tuple[PermutationType, set[str], str]] = [
        (
            PermutationType.HOMOGLYPH,
            {v for v in homoglyph_variants if v.isascii()},
            "visually identical character",
        ),
        (
            PermutationType.IDN,
            idn_squats(homoglyph_variants),
            "ACE/punycode unicode homoglyph",
        ),
        (PermutationType.TYPO, rule_typos(label), "typo / keyboard error"),
        (PermutationType.BITSQUAT, rule_bitsquats(label), "bit-flip (memory error)"),
        (PermutationType.HYPHEN, rule_hyphenation(label), "hyphen modification"),
        (PermutationType.SOUNDSQUAT, rule_soundsquats(label), "phonetic substitution"),
        (PermutationType.VOWEL_SWAP, rule_vowel_swaps(label), "vowel substitution"),
        (PermutationType.PLURAL, rule_plurals(label), "plural/singular variation"),
        (PermutationType.COMBO, rule_combos(label, tld), "appended bait word"),
        (
            PermutationType.WWW_MERGE,
            rule_www_merge(label),
            "'www' merged into domain (dot omission)",
        ),
    ]

    for kind, variants, note in pipeline:
        for v in sorted(variants):
            fqdn = f"{v}.{tld}" if tld else v
            normalized = to_ace(fqdn)
            if normalized is None or normalized in seen:
                continue
            seen.add(normalized)
            result.append(Permutation(domain=normalized, kind=kind, note=note))

    if tld:
        for alt in _ALT_TLDS:
            if alt == tld:
                continue
            swapped = to_ace(f"{label}.{alt}")
            if swapped is None or swapped in seen:
                continue
            seen.add(swapped)
            result.append(
                Permutation(
                    domain=swapped,
                    kind=PermutationType.TLD_SWAP,
                    note=f"different TLD (.{alt})",
                )
            )

    for suffix in _SPOOF_SUFFIXES:
        spoofed = to_ace(f"{base}.{suffix}")
        if spoofed is None or spoofed in seen:
            continue
        seen.add(spoofed)
        result.append(
            Permutation(
                domain=spoofed,
                kind=PermutationType.SUBDOMAIN,
                note=f"original domain as subdomain of .{suffix}",
            )
        )

    return result


__all__ = ["generate"]
