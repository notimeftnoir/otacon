"""Tests for the design-token layer.

The defect these guard against is the one that made this layer necessary: a
colour defined for one surface and forgotten on another, discovered only when
somebody ran the tool with a theme nobody had looked at.
"""

from __future__ import annotations

import re

import pytest

from otacon.core.types import PermutationType, RiskLevel
from otacon.ui.caps import ColorDepth, GlyphLevel, gradient_stops
from otacon.ui.copy import BANDS, FLAGS, TECHNIQUES
from otacon.ui.emit import html_vars, mix, rich_theme, terminal_theme, textual_vars
from otacon.ui.glyphs import ASCII_FALLBACK, SAFE, degrade
from otacon.ui.tokens import MIDNIGHT, THEMES, Palette, get_theme

_HEX = re.compile(r"^#[0-9a-f]{6}$")


@pytest.mark.parametrize("palette", THEMES.values(), ids=lambda p: p.name)
def test_every_theme_defines_every_colour(palette: Palette) -> None:
    """A theme missing a token renders something invisible, not something wrong."""
    for field in (
        "bg",
        "surface",
        "raised",
        "line",
        "line_strong",
        "dim",
        "muted",
        "body",
        "strong",
        "brand",
        "brand_dim",
        "accent",
        "select",
    ):
        value = getattr(palette, field)
        assert _HEX.match(value), f"{palette.name}.{field} = {value!r}"


@pytest.mark.parametrize("palette", THEMES.values(), ids=lambda p: p.name)
def test_every_theme_covers_every_risk_level(palette: Palette) -> None:
    assert set(palette.risk) == set(RiskLevel)
    for level in RiskLevel:
        tone = palette.tone(level)
        assert _HEX.match(tone.fg), f"{palette.name}/{level.value}.fg"
        assert _HEX.match(tone.wash), f"{palette.name}/{level.value}.wash"
        assert tone.sigil and tone.band and tone.label


@pytest.mark.parametrize("palette", THEMES.values(), ids=lambda p: p.name)
def test_every_theme_emits_to_every_surface(palette: Palette) -> None:
    """Each renderer must be constructible from each theme."""
    rich_theme(palette)
    terminal_theme(palette)
    assert set(textual_vars(palette)) == set(textual_vars(MIDNIGHT))
    produced = {kv.split(":", 1)[0] for kv in html_vars(palette).rstrip(";").split(";")}
    expected = {kv.split(":", 1)[0] for kv in html_vars(MIDNIGHT).rstrip(";").split(";")}
    assert produced == expected


def test_risk_sigils_are_ordered_by_ink() -> None:
    """Severity has to survive with no colour, which is what `mono` relies on."""
    ramp = [
        MIDNIGHT.tone(level).sigil
        for level in (
            RiskLevel.SAFE,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        )
    ]
    assert ramp == ["○", "░", "▒", "▓", "█"]


def test_mono_carries_no_hue() -> None:
    """Its whole purpose: NO_COLOR and greyscale screenshots must stay readable."""
    for level in RiskLevel:
        fg = THEMES["mono"].tone(level).fg
        r, g, b = (int(fg[i : i + 2], 16) for i in (1, 3, 5))
        assert r == g == b, f"mono/{level.value} = {fg}"


def test_unknown_theme_falls_back_rather_than_raising() -> None:
    """A stale OTACON_THEME must never be why a scan refuses to run."""
    assert get_theme("nonesuch") is MIDNIGHT
    assert get_theme(None) is MIDNIGHT
    assert get_theme("  VISION ") is THEMES["vision"]


def test_gradient_degrades_instead_of_collapsing() -> None:
    """Below truecolor a four-stop ramp quantises to one flat colour.

    That is what made the wordmark look broken on a 16-colour terminal rather
    than merely plainer, so each depth gets a ramp it can actually resolve.
    """
    assert gradient_stops(MIDNIGHT, ColorDepth.TRUECOLOR) == MIDNIGHT.gradient
    assert len(gradient_stops(MIDNIGHT, ColorDepth.EIGHT_BIT)) == 2
    assert len(gradient_stops(MIDNIGHT, ColorDepth.BASIC)) == 1
    assert len(gradient_stops(MIDNIGHT, ColorDepth.NONE)) == 1


def test_every_budgeted_glyph_has_an_ascii_stand_in() -> None:
    """--ascii is only honest if nothing silently disappears."""
    assert not SAFE - set(ASCII_FALLBACK)


def test_degrade_leaves_nothing_above_ascii() -> None:
    assert degrade("████░░ ✓ ⚠ › 100", GlyphLevel.ASCII).isascii()  # noqa: RUF001
    assert degrade("█ ✓", GlyphLevel.FULL) == "█ ✓"


def test_critical_has_no_background() -> None:
    """It used to, and inside a table cell that read as a rendering fault."""
    style = rich_theme(MIDNIGHT).styles["critical"]
    assert style.bgcolor is None


def test_vocabulary_covers_every_technique() -> None:
    """An unexplained technique is a dead end for the reader the copy is for."""
    assert set(TECHNIQUES) == set(PermutationType)
    for term in list(TECHNIQUES.values()) + list(FLAGS.values()):
        assert term.short and term.long and term.meaning
        assert term.meaning.endswith("."), term.meaning


def test_score_bands_match_the_scoring_engine() -> None:
    """The bands shown to a reader must be the bands the engine actually uses."""
    assert {level for level, _, _ in BANDS} == set(RiskLevel)
    for level, span, _why in BANDS:
        low, high = (int(n) for n in span.split("-"))
        assert RiskLevel.from_score(low) is level, span
        assert RiskLevel.from_score(high) is level, span


def test_mix_blends_toward_the_second_colour() -> None:
    assert mix("#ffffff", "#000000", 0.0) == "#ffffff"
    assert mix("#ffffff", "#000000", 1.0) == "#000000"
    assert mix("#ffffff", "#000000", 0.5) == "#808080"
