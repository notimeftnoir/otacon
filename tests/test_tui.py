"""Tests for the Textual triage console.

Driven through Textual's own pilot so the bindings, the filter chain and the
dossier pane are exercised the way an operator reaches them, rather than by
calling the action methods directly.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from otacon.core.models import DomainResult, ScanReport
from otacon.core.types import PermutationType, RiskLevel
from otacon.tui.app import OtaconTUI
from otacon.tui.screens import ResultsScreen
from otacon.tui.styles import OTACON_CSS
from otacon.tui.widgets import (
    LEVEL_COLOR,
    badges,
    level_counts,
    risk_bar,
    signals,
)
from otacon.ui.emit import rich_theme, textual_vars
from otacon.ui.tokens import MIDNIGHT, THEMES


def _screen(app: OtaconTUI) -> ResultsScreen:
    """The results screen the app is currently showing."""
    screen = app.screen
    assert isinstance(screen, ResultsScreen)
    return screen


def _result(domain: str, score: int, level: RiskLevel, **kw: object) -> DomainResult:
    return DomainResult(
        domain=domain,
        kind=PermutationType.TYPO,
        resolves=True,
        ip_addresses=["1.2.3.4"],
        risk_score=score,
        risk_level=level,
        **kw,  # type: ignore[arg-type]
    )


@pytest.fixture
def report() -> ScanReport:
    return ScanReport(
        target="example.com",
        total_permutations=6,
        results=[
            _result("exampl3.com", 95, RiskLevel.CRITICAL, favicon_matches_target=True),
            _result("exmaple.com", 70, RiskLevel.HIGH, has_login_form=True),
            _result("exampel.com", 40, RiskLevel.MEDIUM, has_mx=True, is_mail_spoofable=True),
            _result("exampie.com", 20, RiskLevel.LOW, is_parked=True),
            DomainResult(domain="nothere.com", kind=PermutationType.TYPO),
        ],
    )


# ── pure helpers ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("score", "filled"),
    [(0, 0), (6, 0), (13, 1), (50, 4), (99, 8), (100, 8)],
)
def test_risk_bar_ramp(score: int, filled: int) -> None:
    bar = risk_bar(score)
    assert len(bar) == 8
    assert bar.count("█") == filled


def test_badges_lists_every_actionable_flag() -> None:
    r = _result(
        "x.com",
        90,
        RiskLevel.CRITICAL,
        dnsbl_listed=True,
        favicon_matches_target=True,
        has_login_form=True,
        has_mx=True,
        is_mail_spoofable=True,
    )
    assert badges(r) == "DBL FAVICON LOGIN SPOOF"


def test_badges_prefers_sinkhole_over_parked() -> None:
    r = _result("x.com", 0, RiskLevel.SAFE, is_sinkhole=True, is_parked=True)
    assert "SINKHOLE" in badges(r)
    assert "PARKED" not in badges(r)


def test_signals_marks_absent_checks_without_shifting_columns() -> None:
    present = signals(_result("a.com", 50, RiskLevel.MEDIUM, has_mx=True, has_ssl=True))
    absent = signals(_result("b.com", 50, RiskLevel.MEDIUM))
    assert present == "DNS MX SSL ···"
    # Absent checks are dotted rather than blank so the column stays aligned.
    assert absent == "DNS ·· ··· ···"


def test_level_counts_ignores_unregistered(report: ScanReport) -> None:
    counts = level_counts(report)
    assert counts[RiskLevel.CRITICAL] == 1
    assert counts[RiskLevel.HIGH] == 1
    assert sum(counts.values()) == 4  # nothere.com is unregistered


def test_stylesheet_carries_no_colours_of_its_own() -> None:
    """The stylesheet must hold design tokens, never literals.

    This replaces an older anti-drift check that asserted styles.py repeated
    the Rich theme's hexes correctly. Repeating them was the defect: the
    stylesheet now references $otacon-* variables fed in from one palette, so
    there is no second copy left to drift. A hex literal reappearing here
    means someone started a third one.
    """
    assert not re.findall(r"#[0-9a-fA-F]{3,8}\b", OTACON_CSS)


def test_every_token_the_stylesheet_uses_is_supplied() -> None:
    """A typo in a $otacon-* name is invisible until something renders wrong."""
    used = set(re.findall(r"\$(otacon-[a-z0-9-]+)", OTACON_CSS))
    supplied = set(textual_vars(MIDNIGHT))
    assert used, "the stylesheet stopped using design tokens"
    assert used <= supplied, f"undefined tokens: {sorted(used - supplied)}"


def test_rich_theme_and_textual_tokens_come_from_one_palette() -> None:
    """The console and the triage console must agree about what 'critical' is."""
    for palette in THEMES.values():
        tokens = textual_vars(palette)
        theme = rich_theme(palette)
        for level in RiskLevel:
            assert tokens[f"otacon-risk-{level.value}"] == palette.tone(level).fg
        brand = theme.styles["brand"].color
        assert brand is not None and brand.triplet is not None
        assert brand.triplet.hex.lower() == palette.brand.lower()


def test_level_colours_are_real_colours() -> None:
    for level, hex_colour in LEVEL_COLOR.items():
        assert hex_colour.startswith("#"), level


# ── driven through the UI ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_opens_on_the_highest_scoring_row(report: ScanReport) -> None:
    app = OtaconTUI(report)
    async with app.run_test() as pilot:
        await pilot.pause()
        assert _screen(app).selected is not None
        assert _screen(app).selected.domain == "exampl3.com"


@pytest.mark.asyncio
async def test_unregistered_hidden_until_toggled(report: ScanReport) -> None:
    app = OtaconTUI(report)
    async with app.run_test() as pilot:
        await pilot.pause()
        assert [r.domain for r in _screen(app)._rows] == [
            "exampl3.com",
            "exmaple.com",
            "exampel.com",
            "exampie.com",
        ]
        await pilot.press("u")
        await pilot.pause()
        assert "nothere.com" in [r.domain for r in _screen(app)._rows]
        await pilot.press("u")
        await pilot.pause()
        assert "nothere.com" not in [r.domain for r in _screen(app)._rows]


@pytest.mark.asyncio
async def test_digit_filters_to_one_level_and_toggles_off(report: ScanReport) -> None:
    app = OtaconTUI(report)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("1")
        await pilot.pause()
        assert [r.domain for r in _screen(app)._rows] == ["exampl3.com"]
        await pilot.press("1")  # same key lifts the filter
        await pilot.pause()
        assert len(_screen(app)._rows) == 4


@pytest.mark.asyncio
async def test_zero_clears_an_active_level_filter(report: ScanReport) -> None:
    app = OtaconTUI(report)
    async with app.run_test() as pilot:
        await pilot.press("2")
        await pilot.pause()
        assert len(_screen(app)._rows) == 1
        await pilot.press("0")
        await pilot.pause()
        assert len(_screen(app)._rows) == 4


@pytest.mark.asyncio
async def test_search_narrows_rows_and_escape_restores_them(report: ScanReport) -> None:
    app = OtaconTUI(report)
    async with app.run_test() as pilot:
        await pilot.press("slash")
        for ch in "exampe":
            await pilot.press(ch)
        await pilot.pause()
        assert [r.domain for r in _screen(app)._rows] == ["exampel.com"]
        await pilot.press("escape")
        await pilot.pause()
        assert len(_screen(app)._rows) == 4


@pytest.mark.asyncio
async def test_navigation_moves_the_dossier(report: ScanReport) -> None:
    app = OtaconTUI(report)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("j")
        await pilot.pause()
        assert _screen(app).selected is not None
        assert _screen(app).selected.domain == "exmaple.com"
        await pilot.press("k")
        await pilot.pause()
        assert _screen(app).selected is not None
        assert _screen(app).selected.domain == "exampl3.com"


@pytest.mark.asyncio
async def test_takedown_overlay_shows_and_escape_dismisses(
    report: ScanReport, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    app = OtaconTUI(report)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("t")
        await pilot.pause()
        notice = _screen(app).query_one("#notice")
        assert notice.has_class("visible")
        written = tmp_path / "takedown-exampl3_com.txt"
        assert written.is_file()
        assert "exampl3[.]com" in written.read_text(encoding="utf-8")
        await pilot.press("escape")
        await pilot.pause()
        assert not notice.has_class("visible")


@pytest.mark.asyncio
async def test_export_writes_a_single_result_report(
    report: ScanReport, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    app = OtaconTUI(report)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        written = tmp_path / "exampl3_com.json"
        assert written.is_file()
        payload = json.loads(written.read_text(encoding="utf-8"))
        assert payload["target"] == "example.com"
        assert len(payload["results"]) == 1
        assert payload["results"][0]["domain"] == "exampl3.com"


@pytest.mark.asyncio
async def test_actions_are_inert_when_the_filter_matches_nothing(
    report: ScanReport, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty row set must not raise or write a file named after nothing."""
    monkeypatch.chdir(tmp_path)
    app = OtaconTUI(report)
    async with app.run_test() as pilot:
        await pilot.press("slash")
        for ch in "zzzz":
            await pilot.press(ch)
        await pilot.pause()
        assert _screen(app)._rows == []
        assert _screen(app).selected is None
        await pilot.press("escape")
        await pilot.press("5")  # no SAFE registered rows in the fixture
        await pilot.pause()
        _screen(app).action_export()
        _screen(app).action_takedown()
        _screen(app).action_whois()
        await pilot.pause()
        assert list(tmp_path.iterdir()) == []


@pytest.mark.asyncio
async def test_unsafe_export_filename_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Row data is attacker-influenced, so the derived filename is contained."""
    monkeypatch.chdir(tmp_path)
    hostile = ScanReport(
        target="example.com",
        results=[_result("nul", 50, RiskLevel.MEDIUM)],
    )
    app = OtaconTUI(hostile)
    async with app.run_test() as pilot:
        await pilot.pause()
        _screen(app).action_export()
        await pilot.pause()
        assert list(tmp_path.iterdir()) == []
