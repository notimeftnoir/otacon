"""``otacon check <link>``: is this link a fake of a brand I know?

The reverse of a scan, for whoever received a suspicious link rather than
for the brand owner: take one host, work out which well-known brand it
imitates (or the one named with --brand), and run the same signals on it as
a scan would, plus phishing feeds.

Safety for the person checking: only the domain's front page is ever
fetched, never the path or query of the pasted link, where tracking tokens
that would tell the attacker "this victim clicked" usually live.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from . import __version__, intel, scoring
from ._validate import is_valid_domain, normalize_domain
from .models import DomainResult, Permutation, PermutationType
from .permutations import _FOLD, _HOMOGLYPHS, _from_ace, _split_domain
from .resolver import Resolver
from .theme import RiskLevel
from .whois import fetch_domain_age

# Often-impersonated brands and their own registrable domains. Polish brands
# first: CERT Polska's phishing reports are dominated by them.
# ponytail: static list; --brand covers anything missing.
BRANDS: dict[str, tuple[str, ...]] = {
    "allegro": ("allegro.pl", "allegrolokalnie.pl", "allegro.cz", "allegrogroup.com"),
    "olx": ("olx.pl", "olx.com", "olx.ua"),
    "inpost": ("inpost.pl", "inpost.eu", "inpost.co.uk"),
    "poczta-polska": ("poczta-polska.pl", "pocztex.pl"),
    "dpd": ("dpd.com", "dpd.pl"),
    "dhl": ("dhl.com", "dhl.pl", "dhl.de"),
    "pkobp": ("pkobp.pl", "ipko.pl", "pko.pl"),
    "mbank": ("mbank.pl",),
    "ing": ("ing.pl", "ing.com", "ing.de"),
    "santander": ("santander.pl", "santander.com"),
    "pekao": ("pekao.com.pl",),
    "millennium": ("bankmillennium.pl",),
    "revolut": ("revolut.com",),
    "blik": ("blik.com",),
    "vinted": ("vinted.pl", "vinted.com"),
    "orlen": ("orlen.pl",),
    "paypal": ("paypal.com", "paypal.me"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com"),
    "outlook": ("outlook.com", "live.com"),
    "apple": ("apple.com", "icloud.com"),
    "google": ("google.com", "google.pl", "gmail.com", "googleusercontent.com"),
    "facebook": ("facebook.com", "fb.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "netflix": ("netflix.com",),
    "amazon": ("amazon.com", "amazon.pl", "amazon.de", "amazonaws.com"),
    "binance": ("binance.com",),
    "coinbase": ("coinbase.com",),
    "github": ("github.com", "githubusercontent.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "dropbox": ("dropbox.com", "dropboxusercontent.com"),
    "linkedin": ("linkedin.com",),
    "steam": ("steampowered.com", "steamcommunity.com"),
    "booking": ("booking.com",),
}

# Characters attackers swap in, mapped back to the letter they imitate.
_GLYPH_TO_LETTER = {
    glyph: letter
    for letter, glyphs in _HOMOGLYPHS.items()
    for glyph in glyphs
    if len(glyph) == 1 and not glyph.isascii()  # digits are _DIGITS' job
}
_DIGITS = str.maketrans("01345", "oleas")
_SUBSTRING_MIN = 5  # shorter brands match whole tokens or prefixes only ("ing" vs "login")
_ESTABLISHED_DAYS = 2 * 365
_CLONED_TITLE = 0.5  # the similarity at which scoring calls a title cloned
_FUZZY_MIN = 6  # a misspelled brand inside a longer label: shorter ones match noise


def skeleton(label: str) -> str:
    """What *label* reads as: homoglyphs, diacritics and digit swaps undone, no hyphens."""
    text = _from_ace(label).lower()
    text = "".join(_GLYPH_TO_LETTER.get(ch, _FOLD.get(ch, ch)) for ch in text)
    return text.replace("rn", "m").replace("vv", "w").translate(_DIGITS).replace("-", "")


def _osa(a: str, b: str) -> int:
    """Optimal-string-alignment edit distance (insert, delete, swap, transpose)."""
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def _fuzzy_contains(text: str, word: str) -> bool:
    """True when some window of *text* is within one edit of *word*.

    Finds 'millenium' inside 'bankmilleniumlogowanie' for 'millennium'.
    """
    n = len(word)
    return any(
        _osa(text[i : i + size], word) <= 1
        for size in (n - 1, n, n + 1)
        for i in range(len(text) - size + 1)
    )


def host_of(link: str) -> tuple[str | None, str | None]:
    """(ACE host, decoy) from a pasted link, defanged or not.

    The decoy is what an ``https://allegro.pl@evil.com/`` link shows before
    the ``@``: browsers treat it as a user name and go to evil.com.
    """
    text = re.sub(r"\[\.\]|\(\.\)|\[dot\]", ".", link.strip(), flags=re.IGNORECASE)
    text = re.sub(r"^hxxp", "http", text, flags=re.IGNORECASE)
    if "://" not in text:
        text = "http://" + text
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return None, None
    if not host:
        return None, None
    host = normalize_domain(host)
    return (host if is_valid_domain(host) else None), parts.username or None


def registrable(host: str) -> str:
    """The part someone registered: 'allegro.id-1.click' -> 'id-1.click'."""
    label, tld = _split_domain(host)
    return f"{label.split('.')[-1]}.{tld}" if tld else host


@dataclass
class Match:
    """Which brand a host imitates, and how."""

    brand: str
    official: tuple[str, ...]
    kind: PermutationType
    how: str


def guess_brand(host: str, brand: str | None = None) -> Match | None:
    """The brand *host* imitates: the given *brand* domain, else the built-in list."""
    candidates = {_split_domain(brand)[0].split(".")[-1]: (brand,)} if brand else BRANDS
    label, _ = _split_domain(host)
    labels = label.split(".")
    own = registrable(host)
    best: tuple[int, Match] | None = None
    for token, official in candidates.items():
        want = skeleton(token)
        for i, lab in enumerate(labels):
            sk = skeleton(lab)
            last = i == len(labels) - 1  # the registered label, not a subdomain
            if sk == want:
                if not last:
                    found = (0, Match(token, official, PermutationType.SUBDOMAIN, "as a subdomain"))
                elif (decoded := _from_ace(lab)) != token:
                    if decoded.isascii():
                        kind = PermutationType.HOMOGLYPH  # a11egro: digits for letters
                    elif "".join(_FOLD.get(ch, ch) for ch in decoded) == token:
                        kind = PermutationType.DIACRITIC  # allęgro
                    else:
                        kind = PermutationType.IDN  # Cyrillic and friends
                    found = (0, Match(token, official, kind, "with lookalike characters"))
                elif own not in official:
                    found = (1, Match(token, official, PermutationType.TLD_SWAP, "on another TLD"))
                else:
                    continue
            elif want in lab.split("-") or (
                len(want) >= _SUBSTRING_MIN and want in sk  # short: whole tokens only
            ):
                kind = PermutationType.COMBO if last else PermutationType.SUBDOMAIN
                found = (2, Match(token, official, kind, "with extra words around it"))
            elif len(want) >= _SUBSTRING_MIN and _osa(sk, want) <= 1:
                found = (3, Match(token, official, PermutationType.TYPO, "with a typo"))
            elif len(want) >= _FUZZY_MIN and _fuzzy_contains(sk, want):
                kind = PermutationType.COMBO if last else PermutationType.SUBDOMAIN
                found = (4, Match(token, official, kind, "misspelled, with extra words"))
            else:
                continue
            if best is None or found[0] < best[0]:
                best = found
    return best[1] if best else None


@dataclass
class CheckResult:
    """Everything ``otacon check`` found about one host."""

    host: str
    # "official" | "reported" | "deceptive" | "impersonation" | "established" | "unknown"
    verdict: str
    match: Match | None = None
    result: DomainResult | None = None
    decoy: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def dangerous(self) -> bool:
        """Worth a red warning: reported, the "@" trick, or a high-risk live fake."""
        if self.verdict in ("reported", "deceptive"):
            return True
        r = self.result
        return (
            self.verdict == "impersonation"
            and r is not None
            and r.risk_level.rank >= RiskLevel.HIGH.rank
        )

    @property
    def show_risk(self) -> bool:
        """Whether a risk score means anything here (a known brand, a live host)."""
        return (
            self.verdict in ("impersonation", "reported", "deceptive")
            and self.result is not None
            and self.result.is_registered
        )


def owner(host: str, brand: str | None = None) -> tuple[str, tuple[str, ...]] | None:
    """(brand, its domains) when *host* is one of a brand's own domains."""
    own = registrable(host)
    if brand:
        return (brand, (brand,)) if own == registrable(brand) else None
    for token, official in BRANDS.items():
        if own in official:
            return token, official
    return None


async def check(
    host: str,
    brand: str | None = None,
    *,
    check_http: bool = True,
    check_intel: bool = True,
    nameservers: list[str] | None = None,
    decoy: str | None = None,
) -> CheckResult:
    """Runs the scan's signals and the phishing feeds on one *host*."""
    real = owner(host, brand)
    if real is not None and not decoy:
        return CheckResult(host, "official", Match(*real, PermutationType.TYPO, ""))

    match = guess_brand(host, brand)
    if decoy:
        # https://allegro.pl@evil.com: the brand is the part before the "@".
        decoy_host, _ = host_of(decoy)
        hidden = owner(decoy_host, brand) if decoy_host else None
        if hidden is None and decoy_host:
            guessed = guess_brand(decoy_host, brand)
            hidden = (guessed.brand, guessed.official) if guessed else None
        if hidden is not None:
            match = Match(*hidden, PermutationType.COMBO, "by hiding behind an '@'")

    own = registrable(host)
    official = match.official[0] if match else ""
    perm = Permutation(
        domain=host,
        kind=match.kind if match else PermutationType.COMBO,
        note=f"imitates {match.brand} {match.how}" if match else "",
    )
    async with Resolver(
        check_http=check_http, target=official, check_whois=False, nameservers=nameservers
    ) as resolver:
        result = await resolver.check_one(perm)
        if result.is_registered:
            result.created_at, result.age_days = await fetch_domain_age(own)
        if check_intel:
            async with httpx.AsyncClient(
                timeout=20.0, headers={"User-Agent": f"Otacon/{__version__}"}
            ) as client:
                feeds = await intel.load_feeds(client)
            listed = intel.match({host, own}, feeds)
            result.intel_sources = sorted({s for hits in listed.values() for s in hits})
        target_favicon = resolver.target_favicon
        # A risk score means "how dangerous as a fake of X": without an X it is noise.
        if match:
            scoring.score(result, official, None, resolver.target_title, target_favicon)

    cloned = (result.title_similarity or 0) >= _CLONED_TITLE or (
        result.favicon_hash is not None and result.favicon_hash == target_favicon
    )
    if result.intel_sources:
        verdict = "reported"
    elif decoy and match:
        verdict = "deceptive"  # the "@" trick has no innocent use
    elif not match:
        verdict = "unknown"
    elif not cloned and result.age_days is not None and result.age_days >= _ESTABLISHED_DAYS:
        # Phishing domains live for days or weeks; one that has been around for
        # years with a merely similar name is usually an unrelated business
        # (applebees.com, steamboat.com). A copied title or icon overrides this.
        verdict = "established"
    else:
        verdict = "impersonation"
    out = CheckResult(host, verdict, match, result, decoy)
    if decoy:
        out.notes.append(
            f"The link shows '{decoy}' before an '@', but browsers go to {host}: a classic trick."
        )
    if verdict == "reported" and not result.is_registered:
        out.notes.append("It is offline now (taken down or expired); the link is still a lure.")
    if result.age_days is not None and result.age_days < scoring.AGE_NEW_DAYS:
        out.notes.append(f"The domain was registered only {result.age_days} days ago.")
    return out
