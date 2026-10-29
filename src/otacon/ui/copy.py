"""One label per concept, shared by every surface.

Before this module the same finding was called ``[cloned-favicon]`` in the
scan output, ``FAVICON`` in the triage console and ``cloned favicon`` in the
HTML report, so a reader moving between them had to work out that three
spellings meant one thing.

Each entry carries three registers:

``short``    the table cell, where width is the binding constraint
``long``     prose, where there is room to be explicit
``meaning``  one plain sentence for the glossary, written for someone who has
             never run a security tool — which is the audience that decides
             whether this tool is usable at all
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.types import PermutationType, RiskLevel, ScanPhase
from .tokens import MIDNIGHT


@dataclass(frozen=True)
class Term:
    """A finding or technique, in the three registers the surfaces need."""

    short: str
    long: str
    meaning: str


FLAGS: dict[str, Term] = {
    "dnsbl": Term(
        "DBL",
        "listed",
        "A public abuse list already reports this domain for spam or phishing.",
    ),
    "favicon": Term(
        "FAVICON",
        "cloned favicon",
        "It serves your exact site icon, so it is copying your brand on purpose.",
    ),
    "login": Term(
        "LOGIN",
        "login form",
        "The page asks for a password, which is how credentials get stolen.",
    ),
    "spoof": Term(
        "SPOOF",
        "spoofable email",
        "It can send mail as this domain and nothing stops a forged sender.",
    ),
    "sinkhole": Term(
        "SINKHOLE",
        "sinkholed",
        "Already seized or redirected by investigators. Nothing left to do.",
    ),
    "parked": Term(
        "PARKED",
        "parked",
        "Registered but holding an ad page, not a working site.",
    ),
    "defensive": Term(
        "OURS",
        "likely yours",
        "It redirects to your own site and sends no mail, so you probably own it.",
    ),
}

TECHNIQUES: dict[PermutationType, Term] = {
    PermutationType.TYPO: Term(
        "typo", "typo", "A slip of the finger: a neighbouring key, or a doubled letter."
    ),
    PermutationType.HOMOGLYPH: Term(
        "homoglyph",
        "look-alike letter",
        "A letter from another alphabet drawn the same, so the name looks identical.",
    ),
    PermutationType.COMBO: Term(
        "combosquat",
        "added word",
        "Your name plus a word like 'secure' or 'login' that makes it sound official.",
    ),
    PermutationType.TLD_SWAP: Term(
        "tld-swap", "other ending", "The same name under a different ending, like .net or .co."
    ),
    PermutationType.BITSQUAT: Term(
        "bitsquat",
        "one bit off",
        "One flipped bit in memory lands here. Rare, but it needs no mistake at all.",
    ),
    PermutationType.HYPHEN: Term(
        "hyphenation", "hyphenated", "A hyphen added or removed inside the name."
    ),
    PermutationType.SOUNDSQUAT: Term(
        "soundsquat", "sounds alike", "Spelled differently, pronounced the same."
    ),
    PermutationType.SUBDOMAIN: Term(
        "subdomain",
        "fake subdomain",
        "Your name pushed left of the real one, so it reads like your subdomain.",
    ),
    PermutationType.VOWEL_SWAP: Term(
        "vowel-swap", "swapped vowel", "One vowel exchanged for another."
    ),
    PermutationType.PLURAL: Term("plural", "pluralised", "Your name with an s added or removed."),
    PermutationType.IDN: Term(
        "idn",
        "punycode",
        "Non-Latin letters encoded as 'xn--'. Browsers may show it as your name.",
    ),
    PermutationType.WWW_MERGE: Term(
        "www-merge", "www glued on", "The 'www.' run together with the name."
    ),
    PermutationType.CT_LOG: Term(
        "ct-log",
        "found via certificate",
        "Not guessed — it already holds a certificate naming something like you.",
    ),
}

# Score bands, as a reader rather than the scoring engine sees them.
# The ranges mirror RiskLevel.from_score; a test keeps them honest.
BANDS: tuple[tuple[RiskLevel, str, str], ...] = (
    (RiskLevel.CRITICAL, "80-100", "Set up to attack your users. Start here."),
    (RiskLevel.HIGH, "60-79", "Registered and working. Look at it today."),
    (RiskLevel.MEDIUM, "35-59", "Live, with some of the signs of a fake."),
    (RiskLevel.LOW, "15-34", "Exists, but shows little sign of being used."),
    (RiskLevel.SAFE, "0-14", "Parked, yours, or doing nothing at all."),
)


# What each stage of a scan is actually doing, said to the person waiting.
# "DISCOVERING" means nothing; "looking for certificates" means the wait has a
# reason, which is the difference between a pause and a hang.
PHASES: dict[ScanPhase, str] = {
    ScanPhase.GENERATING: "Building the list of lookalikes an attacker could register",
    ScanPhase.DISCOVERING: "Looking for certificates already issued for names like yours",
    ScanPhase.CHECKING: "Checking which of them exist",
}


def band_label(level: RiskLevel) -> str:
    """The four-character gutter label for *level*."""
    return MIDNIGHT.tone(level).band


def level_meaning(level: RiskLevel) -> str:
    """What *level* means for the reader, in one phrase."""
    return MIDNIGHT.tone(level).label


__all__ = ["BANDS", "FLAGS", "PHASES", "TECHNIQUES", "Term", "band_label", "level_meaning"]
