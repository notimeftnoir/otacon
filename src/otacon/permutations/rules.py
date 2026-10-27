"""Permutation rule definitions for generating domain impersonation variants."""

from __future__ import annotations

# Adjacency tables for QWERTY, QWERTZ, AZERTY keyboard layouts
_QWERTY_ADJACENT: dict[str, str] = {
    "q": "was",
    "w": "qeas",
    "e": "wrds",
    "r": "etdf",
    "t": "rygf",
    "y": "tuhg",
    "u": "yijh",
    "i": "uokj",
    "o": "iplk",
    "p": "ol",
    "a": "qwsz",
    "s": "awedxz",
    "d": "serfcx",
    "f": "drtgvc",
    "g": "ftyhbv",
    "h": "gyujnb",
    "j": "huiknm",
    "k": "jiolm",
    "l": "kop",
    "z": "asx",
    "x": "zsdc",
    "c": "xdfv",
    "v": "cfgb",
    "b": "vghn",
    "n": "bhjm",
    "m": "njk",
}


def _swap_layout(base: dict[str, str], pairs: list[tuple[str, str]]) -> dict[str, str]:
    """Derives layout from QWERTY by swapping key positions."""
    trans_map: dict[str, str] = {}
    for a, b in pairs:
        trans_map[a] = b
        trans_map[b] = a
    trans = str.maketrans(trans_map)
    return {key.translate(trans): neighbors.translate(trans) for key, neighbors in base.items()}


_QWERTZ_ADJACENT: dict[str, str] = _swap_layout(_QWERTY_ADJACENT, [("y", "z")])
_AZERTY_ADJACENT: dict[str, str] = _swap_layout(_QWERTY_ADJACENT, [("q", "a"), ("w", "z")])

_KEYBOARD_LAYOUTS: tuple[dict[str, str], ...] = (
    _QWERTY_ADJACENT,
    _QWERTZ_ADJACENT,
    _AZERTY_ADJACENT,
)

# Homoglyphs matching Unicode confusables and real-world observed impersonations
_HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["\u0430", "4"],
    "b": ["\u044c"],
    "c": ["\u0441"],
    "e": ["\u0435", "3"],
    "f": ["\u0192"],
    "g": ["\u0261"],
    "h": ["\u04bb"],
    "i": ["1", "l", "\u00ed", "\u0131"],
    "j": ["\u0458"],
    "k": ["\u043a"],
    "l": ["1", "i", "\u0142"],
    "n": ["\u043f"],
    "o": ["\u043e", "0", "\u03bf"],
    "p": ["\u0440"],
    "q": ["\u051b"],
    "r": ["\u0433"],
    "s": ["\u0455", "5"],
    "t": ["\u0442"],
    "u": ["\u057d"],
    "v": ["\u03bd"],
    "x": ["\u0445"],
    "y": ["\u0443"],
    "z": ["\u1d22"],
    "m": ["rn"],
    "w": ["vv"],
    "d": ["cl"],
}

_SOUND_ALIASES: list[tuple[str, str]] = [
    ("ph", "f"),
    ("f", "ph"),
    ("ck", "k"),
    ("c", "k"),
    ("k", "c"),
    ("z", "s"),
    ("s", "z"),
    ("x", "ks"),
    ("ks", "x"),
]

_SPOOF_SUFFIXES: tuple[str, ...] = (
    "login.com",
    "login.net",
    "secure.net",
    "update.com",
    "verify.org",
    "auth.io",
    "account.net",
    "portal.com",
)

_VOWELS = "aeiou"

_COMBO_KEYWORDS: tuple[str, ...] = (
    "login",
    "secure",
    "account",
    "verify",
    "support",
    "update",
    "auth",
    "signin",
    "billing",
    "service",
    "mail",
    "vpn",
    "portal",
)

_REGIONAL_COMBO_KEYWORDS: dict[str, tuple[str, ...]] = {
    "pl": (
        "faktura",
        "platnosc",
        "bramka",
        "paczka",
        "dostawa",
        "pomoc",
        "panel",
        "zamowienie",
        "klient",
        "logowanie",
    ),
    "de": (
        "rechnung",
        "zahlung",
        "kunde",
        "hilfe",
        "service",
        "konto",
    ),
    "fr": (
        "facture",
        "paiement",
        "client",
        "livraison",
        "espace",
    ),
}

_ALT_TLDS: tuple[str, ...] = (
    "com",
    "net",
    "org",
    "io",
    "co",
    "info",
    "online",
    "site",
    "xyz",
    "app",
    "dev",
    "live",
    "shop",
    "store",
    "biz",
    "top",
    "click",
    "link",
    "cc",
    "pw",
    "club",
    "vip",
    "win",
    "cyou",
    "icu",
    "buzz",
    "pl",
    "de",
    "uk",
    "eu",
    "fr",
)

_COMMON_MULTI_TLDS: set[str] = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "me.uk",
    "ltd.uk",
    "plc.uk",
    "net.uk",
    "com.pl",
    "org.pl",
    "net.pl",
    "edu.pl",
    "gov.pl",
    "info.pl",
    "waw.pl",
    "com.br",
    "org.br",
    "net.br",
    "co.jp",
    "org.jp",
    "ad.jp",
    "ne.jp",
    "com.cn",
    "org.cn",
    "net.cn",
    "gov.cn",
    "com.tw",
    "org.tw",
    "net.tw",
    "co.za",
    "org.za",
    "net.za",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "co.nz",
    "net.nz",
    "org.nz",
    "com.tr",
    "org.tr",
    "net.tr",
    "com.sg",
    "org.sg",
    "net.sg",
}


def split_domain(domain: str) -> tuple[str, str]:
    """Splits a domain into (label, tld), handling multi-label public suffixes like .co.uk."""
    parts = domain.lower().strip().rstrip(".").split(".")
    if len(parts) < 2:
        return parts[0], ""
    if len(parts) >= 3:
        last_two = f"{parts[-2]}.{parts[-1]}"
        if last_two in _COMMON_MULTI_TLDS:
            return ".".join(parts[:-2]), last_two
    return ".".join(parts[:-1]), parts[-1]


def rule_typos(label: str) -> set[str]:
    """Generates omission, duplication, transposition, and keyboard substitution typos."""
    out: set[str] = set()
    for i in range(len(label)):
        out.add(label[:i] + label[i + 1 :])
    for i in range(len(label)):
        out.add(label[:i] + label[i] + label[i:])
    for i in range(len(label) - 1):
        out.add(label[:i] + label[i + 1] + label[i] + label[i + 2 :])
    for i, ch in enumerate(label):
        for layout in _KEYBOARD_LAYOUTS:
            for adj in layout.get(ch, ""):
                out.add(label[:i] + adj + label[i + 1 :])
                out.add(label[:i] + adj + label[i:])
                out.add(label[: i + 1] + adj + label[i + 1 :])
    out.discard(label)
    out.discard("")
    return out


def rule_homoglyphs(label: str) -> set[str]:
    """Substitutes single characters with visual look-alikes."""
    out: set[str] = set()
    for i, ch in enumerate(label):
        for glyph in _HOMOGLYPHS.get(ch, []):
            out.add(label[:i] + glyph + label[i + 1 :])
    out.discard(label)
    return out


def rule_combos(label: str, tld: str = "") -> set[str]:
    """Appends security and bait keywords with and without hyphens."""
    out: set[str] = set()
    keywords = list(_COMBO_KEYWORDS)
    tld_key = tld.split(".")[-1].lower() if tld else ""
    if tld_key in _REGIONAL_COMBO_KEYWORDS:
        keywords.extend(_REGIONAL_COMBO_KEYWORDS[tld_key])
    for kw in keywords:
        out.add(f"{label}-{kw}")
        out.add(f"{label}{kw}")
        out.add(f"{kw}-{label}")
        out.add(f"{kw}{label}")
    return out


def rule_bitsquats(label: str) -> set[str]:
    """Generates bit-flipped ASCII alphanumeric characters."""
    out: set[str] = set()
    for i, ch in enumerate(label):
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit))
            if flipped.isalnum() and flipped.isascii():
                out.add(label[:i] + flipped.lower() + label[i + 1 :])
    out.discard(label)
    return out


def rule_hyphenation(label: str) -> set[str]:
    """Inserts hyphens between characters and removes existing ones."""
    out: set[str] = set()
    for i in range(1, len(label)):
        if label[i - 1] == "." or label[i] == ".":
            continue
        out.add(label[:i] + "-" + label[i:])
    if "-" in label:
        out.add(label.replace("-", ""))
    return out


def rule_soundsquats(label: str) -> set[str]:
    """Substitutes sound-alike phonetic sequences (ph/f, c/k, s/z)."""
    out: set[str] = set()
    for old, new in _SOUND_ALIASES:
        start = 0
        while (idx := label.find(old, start)) != -1:
            out.add(label[:idx] + new + label[idx + len(old) :])
            start = idx + 1
    out.discard(label)
    out.discard("")
    return out


def rule_vowel_swaps(label: str) -> set[str]:
    """Replaces each vowel with every other vowel."""
    out: set[str] = set()
    for i, ch in enumerate(label):
        if ch in _VOWELS:
            for v in _VOWELS:
                if v != ch:
                    out.add(label[:i] + v + label[i + 1 :])
    out.discard(label)
    return out


def rule_plurals(label: str) -> set[str]:
    """Generates singular and plural variations."""
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


def rule_www_merge(label: str) -> set[str]:
    """Merges 'www' into the domain label without a dot."""
    if label.startswith("www"):
        return set()
    return {"www" + label}


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
]
