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
    """Derives another keyboard layout from QWERTY by swapping key positions.

    Each (a, b) pair is a physical key position whose printed letters swap —
    matching how real layouts differ from QWERTY (QWERTZ swaps y/z; AZERTY
    swaps q/a and w/z). Both the dict keys and the neighbor strings are
    swapped, since a swapped key also changes what it's a neighbor of.
    """
    trans_map: dict[str, str] = {}
    for a, b in pairs:
        trans_map[a] = b
        trans_map[b] = a
    trans = str.maketrans(trans_map)
    return {key.translate(trans): neighbors.translate(trans) for key, neighbors in base.items()}


# QWERTZ (DE/AT/CH) and AZERTY (FR) — the next most common layouts after
# QWERTY, relevant when the target audience isn't US/UK-centric.
_QWERTZ_ADJACENT: dict[str, str] = _swap_layout(_QWERTY_ADJACENT, [("y", "z")])
_AZERTY_ADJACENT: dict[str, str] = _swap_layout(_QWERTY_ADJACENT, [("q", "a"), ("w", "z")])

_KEYBOARD_LAYOUTS: tuple[dict[str, str], ...] = (
    _QWERTY_ADJACENT,
    _QWERTZ_ADJACENT,
    _AZERTY_ADJACENT,
)

# Homoglyphs: visually similar characters. We mix ASCII (1/l, 0/o) with
# Unicode (Cyrillic/Greek/Armenian), since both are used in real-world attacks.
# Non-ASCII entries are cross-checked against Unicode's confusables.txt
# (unicode.org/Public/security/latest/confusables.txt) \u2014 each is a documented
# single-codepoint confusable for that Latin letter, not a guess.
_HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["\u0430", "4"],  # Cyrillic a  (@ removed \u2014 invalid DNS char)
    "b": ["\u044c"],  # Cyrillic soft sign \u044c
    "c": ["\u0441"],  # Cyrillic c  (( removed \u2014 invalid DNS char)
    "e": ["\u0435", "3"],  # Cyrillic e
    "f": ["\u0192"],  # Latin small letter f with hook \u0192
    "g": ["\u0261"],  # Latin small letter script g \u0261
    "h": ["\u04bb"],  # Cyrillic shha \u04bb
    "i": ["1", "l", "\u00ed", "\u0131"],
    "j": ["\u0458"],  # Cyrillic je \u0458
    "k": ["\u043a"],  # Cyrillic ka \u043a
    "l": ["1", "i", "\u0142"],
    "n": ["\u043f"],
    "o": ["\u043e", "0", "\u03bf"],  # Cyrillic o + Greek omicron
    "p": ["\u0440"],  # Cyrillic p
    "q": ["\u051b"],  # Cyrillic qa \u051b
    "r": ["\u0433"],  # Cyrillic ghe \u0433
    "s": ["\u0455", "5"],  # Cyrillic s  ($ removed \u2014 invalid DNS char)
    "t": ["\u0442"],  # Cyrillic te \u0442
    "u": ["\u057d"],  # Armenian seh \u057d
    "v": ["\u03bd"],  # Greek nu \u03bd
    "x": ["\u0445"],  # Cyrillic x
    "y": ["\u0443"],  # Cyrillic y
    "z": ["\u1d22"],  # Latin letter small capital z \u1d22
    "m": ["rn"],  # classic: rn looks like m
    "w": ["vv"],
    "d": ["cl"],
}

# Phonetic substitution pairs — how words *sound* can look like the original.
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

# Suffixes used in subdomain spoofing — attacker registers these and puts the
# real domain as a subdomain label (e.g. paypal.com.login.net).
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

# Words appended in combosquatting — typical for phishing.
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

# Alternative TLDs — where attackers most often register fakes. Includes the
# TLDs most frequently flagged for abuse in Interisle/Spamhaus reporting
# (cheap or historically low-friction registration: top, cyou, icu, cc, pw,
# club, vip, win, buzz, click, link, biz).
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
)


_COMMON_MULTI_TLDS: set[str] = {
    "co.uk",
    "org.uk",
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


def _split_domain(domain: str) -> tuple[str, str]:
    """Splits a domain into (label, tld). 'example.com' -> ('example', 'com').
    'example.co.uk' -> ('example', 'co.uk').

    Strips a trailing root dot (e.g. 'example.com.', a form ``is_valid_domain``
    accepts as a legal FQDN) — without this, the label/tld split collapses onto
    the empty final part and every technique that appends ``tld`` silently
    degrades: TLD_SWAP is skipped outright, and typo/homoglyph mutations land
    inside what should have been the TLD instead of the label.
    """
    parts = domain.lower().strip().rstrip(".").split(".")
    if len(parts) < 2:
        return parts[0], ""
    if len(parts) >= 3:
        last_two = f"{parts[-2]}.{parts[-1]}"
        if last_two in _COMMON_MULTI_TLDS:
            return ".".join(parts[:-2]), last_two
    return ".".join(parts[:-1]), parts[-1]


def _typos(label: str) -> set[str]:
    """Typos: omission, duplication, adjacent transposition, keyboard swap."""
    out: set[str] = set()

    # Character omission.
    for i in range(len(label)):
        out.add(label[:i] + label[i + 1 :])

    # Character duplication (repeats the existing character).
    for i in range(len(label)):
        out.add(label[:i] + label[i] + label[i:])

    # Adjacent character transposition.
    for i in range(len(label) - 1):
        out.add(label[:i] + label[i + 1] + label[i] + label[i + 2 :])

    # Wrong key by keyboard adjacency (replacement) — QWERTY, QWERTZ, AZERTY.
    for i, ch in enumerate(label):
        for layout in _KEYBOARD_LAYOUTS:
            for adj in layout.get(ch, ""):
                out.add(label[:i] + adj + label[i + 1 :])

    out |= _keyboard_insertions(label)

    out.discard(label)
    out.discard("")
    return out


def _keyboard_insertions(label: str) -> set[str]:
    """Inserts an adjacent-key character next to each existing character,
    keeping the original in place — e.g. 'test' -> 'rtest', 'trest'.

    Distinct from duplication (which repeats the existing character): this
    simulates hitting a neighboring key in addition to, not instead of, the
    intended one.
    """
    out: set[str] = set()
    for i, ch in enumerate(label):
        for layout in _KEYBOARD_LAYOUTS:
            for adj in layout.get(ch, ""):
                out.add(label[:i] + adj + label[i:])  # before
                out.add(label[: i + 1] + adj + label[i + 1 :])  # after
    out.discard(label)
    return out


def _homoglyphs(label: str) -> set[str]:
    """Replaces single characters with visual look-alikes.

    We generate variants with ONE substitution at a time — enough to make a
    domain look identical, while avoiding combinatorial explosion.
    """
    out: set[str] = set()
    for i, ch in enumerate(label):
        for glyph in _HOMOGLYPHS.get(ch, []):
            out.add(label[:i] + glyph + label[i + 1 :])
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
                out.add(label[:i] + flipped.lower() + label[i + 1 :])
    out.discard(label)
    return out


def _hyphenation(label: str) -> set[str]:
    """Inserts a hyphen between characters (and removes it if already present).

    *label* keeps its dots for multi-label targets ('foo.example'), so positions
    touching a dot are skipped: RFC 1035 forbids a label starting or ending with
    a hyphen, and 'foo-.example.com' is an unregistrable string that would only
    burn a DNS query.
    """
    out: set[str] = set()
    for i in range(1, len(label)):
        if label[i - 1] == "." or label[i] == ".":
            continue
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
            out.add(label[:idx] + new + label[idx + len(old) :])
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
                    out.add(label[:i] + v + label[i + 1 :])
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


def _www_merge(label: str) -> set[str]:
    """'www' collapsed into the domain with no dot — e.g. wwwexample.com.

    A very common real-world phishing vector: users misread "www.example.com"
    as one label when the dot is dropped.
    """
    if label.startswith("www"):
        return set()
    return {"www" + label}


def _to_ace(fqdn: str) -> str | None:
    """Canonicalises *fqdn* to its ASCII-compatible (punycode) form, or None.

    Every domain this module emits goes through here, so a variant is
    represented exactly one way no matter which technique produced it —
    otherwise the same name reached ``seen`` as Unicode from one generator and
    as ``xn--`` from another, and both were emitted. None means the string is
    not encodable as a domain at all (empty or over-long label), which is the
    signal to drop the variant.
    """
    try:
        return fqdn.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _idn_squats(homoglyph_variants: set[str]) -> set[str]:
    """Punycode-encode non-ASCII homoglyph variants → xn-- ACE labels.

    Takes the already-computed homoglyph set rather than the label, so callers
    that need both the ASCII and non-ASCII homoglyph output (see generate())
    compute ``_homoglyphs(label)`` only once.
    """
    out: set[str] = set()
    for variant in homoglyph_variants:
        if variant.isascii():
            continue
        try:
            ace = variant.encode("idna").decode("ascii")
            if ace.startswith("xn--"):
                out.add(ace)
        except UnicodeError:
            continue
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

    # Canonical form of the input, used everywhere below that needs the full
    # domain rather than its parts. The trailing root dot goes so a dotted FQDN
    # (e.g. 'example.net.') matches the dotless variants every technique emits —
    # mirrors _split_domain.
    # ACE form, so it compares against the punycode the pipeline emits.
    base = _to_ace(domain.lower().strip().rstrip(".")) or domain.lower().strip().rstrip(".")

    # Original domain + whitelist start in `seen` => they will be skipped.
    seen: set[str] = {base}
    if exclude:
        # Whitelist entries go through the same ACE canonicalisation as the
        # variants they are matched against; without it a Unicode entry
        # ('--exclude exampĺe.com') could never match the 'xn--' form every
        # technique emits, and the exclusion was silently dead.
        for entry in exclude:
            cleaned = entry.lower().strip().rstrip(".")
            if not cleaned:
                continue
            seen.add(_to_ace(cleaned) or cleaned)

    result: list[Permutation] = []

    # Computed once and shared below — IDN squats are just the non-ASCII half
    # of the same homoglyph substitutions the HOMOGLYPH technique already needs.
    homoglyph_variants = _homoglyphs(label)

    # Order = priority during deduplication.
    # Homoglyphs and typos are the most dangerous, so they go first.
    pipeline: list[tuple[PermutationType, set[str], str]] = [
        (
            PermutationType.HOMOGLYPH,
            {v for v in homoglyph_variants if v.isascii()},
            "visually identical character",
        ),
        (
            PermutationType.IDN,
            _idn_squats(homoglyph_variants),
            "ACE/punycode unicode homoglyph",
        ),
        (PermutationType.TYPO, _typos(label), "typo / keyboard error"),
        (PermutationType.BITSQUAT, _bitsquats(label), "bit-flip (memory error)"),
        (PermutationType.HYPHEN, _hyphenation(label), "hyphen modification"),
        (PermutationType.SOUNDSQUAT, _soundsquats(label), "phonetic substitution"),
        (PermutationType.VOWEL_SWAP, _vowel_swaps(label), "vowel substitution"),
        (PermutationType.PLURAL, _plurals(label), "plural/singular variation"),
        (PermutationType.COMBO, _combos(label), "appended bait word"),
        (PermutationType.WWW_MERGE, _www_merge(label), "'www' merged into domain (dot omission)"),
    ]

    for kind, variants, note in pipeline:
        for v in sorted(variants):
            fqdn = f"{v}.{tld}" if tld else v

            # Normalize to Punycode (ACE) for strict deduplication.
            # A domain might be Unicode from one technique and Punycode from another.
            normalized = _to_ace(fqdn)
            if normalized is None:
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
            swapped = _to_ace(f"{label}.{alt}")
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

    # Subdomain spoof — original domain embedded as a label in a spoof registrar.
    for suffix in _SPOOF_SUFFIXES:
        spoofed = _to_ace(f"{base}.{suffix}")
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
