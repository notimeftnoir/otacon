"""The palette: one source of visual truth for every surface Otacon renders.

Four surfaces draw the same report — the Rich console, the Textual triage
console, the HTML report and the SVG screenshots in the README. Until this
module existed each of them carried its own hard-coded copy of the colours,
so changing one accent meant three edits and the copies drifted anyway.

Everything here is pure data. No Rich, no Textual, no I/O: ``emit.py`` turns a
``Palette`` into whatever a given renderer wants, and a test asserts the four
themes are complete, so a surface cannot acquire a colour the others lack.

Themes exist for reasons, not variety:

``midnight``  the default dark palette, unchanged from what shipped before.
``daylight``  light terminals, and HTML that someone will print.
``vision``    red/green is the most common colour-vision deficiency and it is
              exactly our critical/safe pair, so this ramp runs blue → amber
              → vermillion (Okabe-Ito), which stays ordered under every common
              deficiency.
``mono``      no hue at all. Severity is carried by the density glyph and by
              weight, which is also what ``NO_COLOR`` resolves to.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ..core.types import RiskLevel


@dataclass(frozen=True)
class RiskTone:
    """How one risk level looks, everywhere it is drawn.

    ``sigil`` doubles as the severity encoding in the ``mono`` theme and in
    the distribution bar of the verdict card, which is why it is a density
    ramp rather than five arbitrary symbols: it stays ordered with no colour
    at all.
    """

    fg: str
    """Score, bar, gutter sigil and band label."""

    wash: str
    """Barely-there row tint, for the selected row inside this band."""

    sigil: str
    """Density glyph. Ordered: the higher the risk, the more ink."""

    band: str
    """Four-character band label for the table gutter."""

    label: str
    """What this level means to a reader who is not a security specialist."""


@dataclass(frozen=True)
class Palette:
    """A complete theme: neutrals, brand, and a tone per risk level."""

    name: str
    dark: bool

    # Neutral scale, back to front. Three surface levels give the interface
    # depth; before this there was one background everywhere and it read flat.
    bg: str
    surface: str
    raised: str
    line: str
    line_strong: str
    dim: str
    muted: str
    body: str
    strong: str

    # Brand and interaction.
    brand: str
    brand_dim: str
    accent: str
    select: str
    """Background of the focused row — the one place a strong tint is earned."""

    risk: Mapping[RiskLevel, RiskTone]
    gradient: tuple[str, ...]
    """Wordmark ramp. ``caps.gradient_stops`` degrades it for poorer terminals."""

    def tone(self, level: RiskLevel) -> RiskTone:
        """The tone for *level*."""
        return self.risk[level]


# Labels and sigils are theme-independent: they are the vocabulary, not the
# paint. Keeping them in one place is what stops `crit`/`critical`/`CRIT`
# appearing on three different surfaces.
_BANDS: dict[RiskLevel, tuple[str, str, str]] = {
    # level: (sigil, band label, plain-language meaning)
    RiskLevel.CRITICAL: ("█", "CRIT", "act now"),
    RiskLevel.HIGH: ("▓", "HIGH", "look today"),
    RiskLevel.MEDIUM: ("▒", "MED", "worth a look"),
    RiskLevel.LOW: ("░", "LOW", "keep an eye on it"),
    RiskLevel.SAFE: ("○", "OK", "harmless"),
}


def _tones(colours: Mapping[RiskLevel, tuple[str, str]]) -> dict[RiskLevel, RiskTone]:
    """Builds the five tones from (foreground, wash) pairs plus the shared vocabulary."""
    return {
        level: RiskTone(
            fg=fg, wash=wash, sigil=_BANDS[level][0], band=_BANDS[level][1], label=_BANDS[level][2]
        )
        for level, (fg, wash) in colours.items()
    }


MIDNIGHT = Palette(
    name="midnight",
    dark=True,
    bg="#0a0e0f",
    surface="#0d1214",
    raised="#121a1c",
    line="#1c2628",
    line_strong="#2b3a3d",
    dim="#5a5a5a",
    muted="#8a8a8a",
    body="#d0d0d0",
    strong="#ffffff",
    brand="#00d7af",
    brand_dim="#00875f",
    accent="#5fafff",
    select="#16302b",
    risk=_tones(
        {
            RiskLevel.CRITICAL: ("#ff5f5f", "#2a1012"),
            RiskLevel.HIGH: ("#ff8f5f", "#2a1a10"),
            RiskLevel.MEDIUM: ("#ffd700", "#2a2410"),
            RiskLevel.LOW: ("#5fafff", "#121d2a"),
            RiskLevel.SAFE: ("#5fd700", "#142611"),
        }
    ),
    gradient=("#00d7af", "#00c0d0", "#00a8e8", "#5f8fff"),
)

DAYLIGHT = Palette(
    name="daylight",
    dark=False,
    bg="#fbfbf9",
    surface="#f2f2ee",
    raised="#e8e8e2",
    line="#d6d6ce",
    line_strong="#b4b4a8",
    dim="#9a9a92",
    muted="#6b6b63",
    body="#2a2a26",
    strong="#000000",
    brand="#00705a",
    brand_dim="#008f73",
    accent="#0057b8",
    select="#d4ebe4",
    risk=_tones(
        {
            # Darkened against a light background: the dark ramp's #ffd700 is
            # unreadable on #fbfbf9 and the HTML report is printed often.
            RiskLevel.CRITICAL: ("#a8001b", "#f7dfe2"),
            RiskLevel.HIGH: ("#b2430a", "#f9e5d8"),
            RiskLevel.MEDIUM: ("#7a5c00", "#f6efd4"),
            RiskLevel.LOW: ("#0057b8", "#dde8f8"),
            RiskLevel.SAFE: ("#2a6e00", "#e2f1d8"),
        }
    ),
    gradient=("#00705a", "#007086", "#00609e", "#2d4fb8"),
)

VISION = Palette(
    name="vision",
    dark=True,
    bg="#0a0e0f",
    surface="#0d1214",
    raised="#121a1c",
    line="#1c2628",
    line_strong="#2b3a3d",
    dim="#5a5a5a",
    muted="#8a8a8a",
    body="#d0d0d0",
    strong="#ffffff",
    brand="#56b4e9",
    brand_dim="#0072b2",
    accent="#56b4e9",
    select="#132433",
    risk=_tones(
        {
            # Okabe-Ito, ordered by warmth rather than by hue, so the ramp
            # survives deuteranopia, protanopia and tritanopia alike.
            RiskLevel.CRITICAL: ("#d55e00", "#2e1505"),
            RiskLevel.HIGH: ("#e69f00", "#2d2206"),
            RiskLevel.MEDIUM: ("#f0e442", "#2b2a10"),
            RiskLevel.LOW: ("#56b4e9", "#122532"),
            RiskLevel.SAFE: ("#0072b2", "#0c1b26"),
        }
    ),
    gradient=("#56b4e9", "#3f9fd4", "#2a8abd", "#0072b2"),
)

MONO = Palette(
    name="mono",
    dark=True,
    bg="#000000",
    surface="#0d0d0d",
    raised="#161616",
    line="#2a2a2a",
    line_strong="#3d3d3d",
    dim="#585858",
    muted="#8a8a8a",
    body="#c6c6c6",
    strong="#ffffff",
    brand="#ffffff",
    brand_dim="#8a8a8a",
    accent="#ffffff",
    select="#2a2a2a",
    risk=_tones(
        {
            # Lightness is the only channel left, so it carries the ordering;
            # the density sigil carries it again for anyone reading a
            # screenshot in greyscale.
            RiskLevel.CRITICAL: ("#ffffff", "#2a2a2a"),
            RiskLevel.HIGH: ("#d0d0d0", "#1f1f1f"),
            RiskLevel.MEDIUM: ("#a0a0a0", "#191919"),
            RiskLevel.LOW: ("#787878", "#141414"),
            RiskLevel.SAFE: ("#585858", "#101010"),
        }
    ),
    gradient=("#ffffff",),
)

THEMES: Mapping[str, Palette] = {p.name: p for p in (MIDNIGHT, DAYLIGHT, VISION, MONO)}

DEFAULT_THEME = MIDNIGHT.name


def get_theme(name: str | None) -> Palette:
    """The palette called *name*, falling back to the default for anything unknown.

    Unknown names fall back rather than raising: a theme is chrome, and an
    environment variable left over from another tool must never be the reason
    a scan refuses to run.
    """
    if not name:
        return THEMES[DEFAULT_THEME]
    return THEMES.get(name.strip().lower(), THEMES[DEFAULT_THEME])


__all__ = [
    "DAYLIGHT",
    "DEFAULT_THEME",
    "MIDNIGHT",
    "MONO",
    "THEMES",
    "VISION",
    "Palette",
    "RiskTone",
    "get_theme",
]
