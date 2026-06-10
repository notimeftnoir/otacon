"""Permutation engine — generates domain variants impersonating the original.

This is the heart of Otacon. Each function implements a different technique
used in the wild by attackers for typosquatting / impersonation.

All generators operate purely on the label (without the TLD), and the TLD is
appended at the end — except TLD_SWAP, which deliberately changes it.

The result is deduplicated and never contains the original domain.
"""

from __future__ import annotations

from .models import Permutation, PermutationType

# QWERTY key adjacency — to simulate "fat finger" typos.
_QWERTY_ADJACENT: dict[str, str] = {
    "q": "was", "w": "qeas", "e": "wrds", "r": "etdf", "t": "rygf",
    "y": "tuhg", "u": "yijh", "i": "uokj", "o": "iplk", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc",
    "g": "ftyhbv", "h": "gyujnb", "j": "huiknm", "k": "jiolm",
    "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk",
}

# Homoglyphs: visually similar characters. We mix ASCII (1/l, 0/o) with
# Unicode (Cyrillic), since both are used in real-world attacks.
_HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["\u0430", "4"],            # Cyrillic a  (@ removed \u2014 invalid DNS char)
    "c": ["\u0441"],                 # Cyrillic c  (( removed \u2014 invalid DNS char)
    "e": ["\u0435", "3"],            # Cyrillic e
    "i": ["1", "l", "\u00ed", "\u0131"],
    "l": ["1", "i", "\u0142"],
    "o": ["\u043e", "0", "\u03bf"],  # Cyrillic o + Greek omicron
    "s": ["\u0455", "5"],            # Cyrillic s  ($ removed \u2014 invalid DNS char)
    "p": ["\u0440"],                 # Cyrillic p
    "x": ["\u0445"],                 # Cyrillic x
    "y": ["\u0443"],                 # Cyrillic y
    "n": ["\u043f"],
    "m": ["rn"],                     # classic: rn looks like m
    "w": ["vv"],
    "d": ["cl"],
}

# Phonetic substitution pairs — how words *sound* can look like the original.
_SOUND_ALIASES: list[tuple[str, str]] = [
    ("ph", "f"), ("f", "ph"), ("ck", "k"), ("c", "k"), ("k", "c"),
    ("z", "s"), ("s", "z"), ("x", "ks"), ("ks", "x"),
]

# Suffixes used in subdomain spoofing — attacker registers these and puts the
# real domain as a subdomain label (e.g. paypal.com.login.net).
_SPOOF_SUFFIXES: tuple[str, ...] = (
    "login.com", "login.net", "secure.net", "update.com",
    "verify.org", "auth.io", "account.net", "portal.com",
)

_VOWELS = "aeiou"

# Words appended in combosquatting — typical for phishing.
_COMBO_KEYWORDS: tuple[str, ...] = (
    "login", "secure", "account", "verify", "support", "update",
    "auth", "signin", "billing", "service", "mail", "vpn", "portal",
)

# Alternative TLDs — where attackers most often register fakes.
_ALT_TLDS: tuple[str, ...] = (
    "com", "net", "org", "io", "co", "info", "online", "site",
    "xyz", "app", "dev", "live", "shop", "store",
)


def _split_domain(domain: str) -> tuple[str, str]:
    """Splits a domain into (label, tld). 'example.com' -> ('example', 'com').

    Simplification: we take the last segment as the TLD. For domains with a
    two-part TLD (e.g. co.uk) the label will contain 'example.co' — acceptable
    for variant generation, since we append/permute anyway.
    """
    parts = domain.lower().strip().split(".")
    if len(parts) < 2:
        return domain.lower(), ""
    return ".".join(parts[:-1]), parts[-1]


def _typos(label: str) -> set[str]:
    """Typos: omission, duplication, adjacent transposition, QWERTY swap."""
    out: set[str] = set()

    # Character omission.
    for i in range(len(label)):
        out.add(label[:i] + label[i + 1:])

    # Character duplication (insertion).
    for i in range(len(label)):
        out.add(label[:i] + label[i] + label[i:])

    # Adjacent character transposition.
    for i in range(len(label) - 1):
        out.add(label[:i] + label[i + 1] + label[i] + label[i + 2:])

    # Wrong key by QWERTY adjacency (replacement).
    for i, ch in enumerate(label):
        for adj in _QWERTY_ADJACENT.get(ch, ""):
            out.add(label[:i] + adj + label[i + 1:])

    out.discard(label)
    out.discard("")
    return out


def _homoglyphs(label: str) -> set[str]:
    """Replaces single characters with visual look-alikes.

    We generate variants with ONE substitution at a time — enough to make a
    domain look identical, while avoiding combinatorial explosion.
    """
    out: set[str] = set()
    for i, ch in enumerate(label):
        for glyph in _HOMOGLYPHS.get(ch, []):
            out.add(label[:i] + glyph + label[i + 1:])
    out.discard(label)
    return out


def _combos(label: str) -> set[str]:
    """Combosquatting: original + bait word, with and without a hyphen."""
    out: set[str] = set()
    for kw in _COMBO_KEYWORDS:
        out.add(f"{label}-{kw}")
        out.add(f"{label}{kw}")
        out.add(f"{kw}-{label}")
        out.add(f"{kw}{label}")
    return out


def _bitsquats(label: str) -> set[str]:
    """Bit-squatting: flip a single bit in a character.

    Real-world vector: RAM/DNS memory errors flip a character and a user lands
    on a different domain. Attackers register these variants to serve malware.
    We keep only alphanumeric variants (the rest are not registrable).
    """
    out: set[str] = set()
    for i, ch in enumerate(label):
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit))
            if flipped.isalnum() and flipped.isascii():
                out.add(label[:i] + flipped.lower() + label[i + 1:])
    out.discard(label)
    return out


def _hyphenation(label: str) -> set[str]:
    """Inserts a hyphen between characters (and removes it if already present)."""
    out: set[str] = set()
    for i in range(1, len(label)):
        out.add(label[:i] + "-" + label[i:])
    if "-" in label:
        out.add(label.replace("-", ""))
    return out


def _soundsquats(label: str) -> set[str]:
    """Phonetic substitution: replace sound-alike sequences (ph/f, c/k, s/z…)."""
    out: set[str] = set()
    for old, new in _SOUND_ALIASES:
        start = 0
        while (idx := label.find(old, start)) != -1:
            out.add(label[:idx] + new + label[idx + len(old):])
            start = idx + 1
    out.discard(label)
    out.discard("")
    return out


def _vowel_swaps(label: str) -> set[str]:
    """Replace each vowel with every other vowel (one substitution at a time)."""
    out: set[str] = set()
    for i, ch in enumerate(label):
        if ch in _VOWELS:
            for v in _VOWELS:
                if v != ch:
                    out.add(label[:i] + v + label[i + 1:])
    out.discard(label)
    return out


def _plurals(label: str) -> set[str]:
    """Singular/plural variation: add -s, strip -s, y <-> ies."""
    out: set[str] = set()
    if label.endswith("ies") and len(label) > 3:
        out.add(label[:-3] + "y")
    elif label.endswith("s") and len(label) > 1:
        out.add(label[:-1])
    else:
        out.add(label + "s")
        if label.endswith("y") and len(label) > 1:
            out.add(label[:-1] + "ies")
    out.discard(label)
    out.discard("")
    return out


def _idn_squats(label: str) -> set[str]:
    """Punycode-encode non-ASCII homoglyph variants → xn-- ACE labels."""
    out: set[str] = set()
    for variant in _homoglyphs(label):
        if variant.isascii():
            continue
        try:
            ace = variant.encode("idna").decode("ascii")
            if ace.startswith("xn--"):
                out.add(ace)
        except UnicodeError:
            continue
    out.discard(label)
    return out


def generate(domain: str, exclude: set[str] | None = None) -> list[Permutation]:
    """Main generator — runs all techniques and deduplicates the result.

    Returns a list of Permutation with metadata (type + technique description),
    without the original domain and without duplicates (first type wins).

    exclude: whitelist of known-good domains (e.g. the owner's legitimate
        aliases). They are added to the `seen` set, so the existing dedup logic
        skips them automatically — and they are never checked over the network.
    """
    label, tld = _split_domain(domain)
    if not label:
        return []

    # Original domain + whitelist start in `seen` => they will be skipped.
    seen: set[str] = {domain.lower()}
    if exclude:
        seen.update(d.lower().strip() for d in exclude)

    result: list[Permutation] = []

    # Order = priority during deduplication.
    # Homoglyphs and typos are the most dangerous, so they go first.
    pipeline: list[tuple[PermutationType, set[str], str]] = [
        (PermutationType.HOMOGLYPH, _homoglyphs(label), "visually identical character"),
        (PermutationType.IDN, _idn_squats(label), "ACE/punycode unicode homoglyph"),
        (PermutationType.TYPO, _typos(label), "typo / keyboard error"),
        (PermutationType.BITSQUAT, _bitsquats(label), "bit-flip (memory error)"),
        (PermutationType.HYPHEN, _hyphenation(label), "hyphen modification"),
        (PermutationType.SOUNDSQUAT, _soundsquats(label), "phonetic substitution"),
        (PermutationType.VOWEL_SWAP, _vowel_swaps(label), "vowel substitution"),
        (PermutationType.PLURAL, _plurals(label), "plural/singular variation"),
        (PermutationType.COMBO, _combos(label), "appended bait word"),
    ]

    for kind, variants, note in pipeline:
        for v in sorted(variants):
            fqdn = f"{v}.{tld}" if tld else v

            # Normalize to Punycode (ACE) for strict deduplication.
            # A domain might be Unicode from one technique and Punycode from another.
            try:
                normalized = fqdn.encode("idna").decode("ascii")
            except UnicodeError:
                continue

            if normalized in seen:
                continue
            seen.add(normalized)
            result.append(Permutation(domain=normalized, kind=kind, note=note))

    # TLD swap — changes the TLD instead of the label.
    if tld:
        for alt in _ALT_TLDS:
            if alt == tld:
                continue
            fqdn = f"{label}.{alt}"
            if fqdn in seen:
                continue
            seen.add(fqdn)
            result.append(
                Permutation(
                    domain=fqdn,
                    kind=PermutationType.TLD_SWAP,
                    note=f"different TLD (.{alt})",
                )
            )

    # Subdomain spoof — original domain embedded as a label in a spoof registrar.
    for suffix in _SPOOF_SUFFIXES:
        fqdn = f"{domain.lower().rstrip('.')}.{suffix}"
        if fqdn in seen:
            continue
        seen.add(fqdn)
        result.append(
            Permutation(
                domain=fqdn,
                kind=PermutationType.SUBDOMAIN,
                note=f"original domain as subdomain of .{suffix}",
            )
        )

    return result
