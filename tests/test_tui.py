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
from textual.coordinate import Coordinate
from textual.widgets import DataTable, Static

from otacon.core.models import DomainResult, ScanReport
from otacon.core.types import PermutationType, RiskLevel
from otacon.tui.app import OtaconTUI
from otacon.tui.screens import ResultsScreen
from otacon.tui.styles import OTACON_CSS
from otacon.tui.widgets import (
    LEVEL_COLOR,
    LEVELS_DESC,
    badges,
    band_cell,
    gutter,
    level_counts,
    risk_bar,
    signals,
    tally,
)
from otacon.ui.copy import BANDS, FLAGS
from otacon.ui.emit import rich_theme, textual_vars
from otacon.ui.tokens import MIDNIGHT, THEMES


def _screen_text(app: OtaconTUI) -> str:
    """Everything currently composited onto the screen, as plain text.

    Asserting against the composited output rather than a widget's renderable
    is the difference between "the code built this" and "a reader can see
    this": anything clipped, scrolled out or covered by an overlay is absent
    here exactly as it is absent on a terminal.
    """
    return "\n".join(
        "".join(segment.text for segment in strip).rstrip()
        for strip in app.screen._compositor.render_strips()
    )


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


# ── hierarchy: the table gutter, bands and tally ────────────────────────


def test_gutter_is_one_cell_of_ordered_ink() -> None:
    """The eight-cell bar it replaces painted one slab down a real scan.

    Scores inside a band rarely differ enough to change a bar's length, so
    thirty rows of `████░░░░` separated nothing while costing the width that
    DOMAIN and FLAGS needed. One glyph gives an edge per row, and the ramp is
    ordered by ink so it survives `mono` and a greyscale screenshot.
    """
    marks = [gutter(level).plain for level in LEVELS_DESC]
    assert marks == ["█", "▓", "▒", "░", "○"]
    assert all(len(m) == 1 for m in marks)


def test_band_label_prints_once_per_run() -> None:
    """Naming each run where it starts is what shows where 'act now' ends."""
    assert band_cell(RiskLevel.HIGH, first_of_band=True).plain == "HIGH"
    assert band_cell(RiskLevel.HIGH, first_of_band=False).plain == ""


def test_tally_is_labelled_by_default(report: ScanReport) -> None:
    """The bare glyph ramp it replaces had no legend anywhere on screen."""
    assert "CRIT" in tally(report).plain
    assert "HIGH" in tally(report).plain


def test_tally_falls_back_to_glyphs_when_labels_will_not_fit(report: ScanReport) -> None:
    bare = tally(report, labelled=False).plain
    assert "CRIT" not in bare
    assert "█" in bare


@pytest.mark.asyncio
async def test_table_shows_a_band_label_at_each_severity_change(report: ScanReport) -> None:
    app = OtaconTUI(report)
    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.pause()
        table = app.screen.query_one("#results", DataTable)
        bands = [table.get_cell_at(Coordinate(row, 0)).plain for row in range(table.row_count)]
    # One label per populated band, in descending order, never repeated.
    assert [b for b in bands if b] == ["CRIT", "HIGH", "MED", "LOW"]


@pytest.mark.asyncio
async def test_focus_mode_dims_everything_below_the_worst_band(report: ScanReport) -> None:
    """Two rows worth acting on should stop competing with thirty that are not."""
    app = OtaconTUI(report)
    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.pause()
        await pilot.press("f")
        await pilot.pause()
        table = app.screen.query_one("#results", DataTable)
        styles = [
            table.get_cell_at(Coordinate(row, 2)).style for row in range(table.row_count)
        ]
    # The critical row keeps its colour; everything under it is dimmed.
    assert MIDNIGHT.dim not in str(styles[0])
    assert all(MIDNIGHT.dim in str(s) for s in styles[1:])


@pytest.mark.asyncio
async def test_bars_toggle_restores_the_full_ramp(report: ScanReport) -> None:
    app = OtaconTUI(report)
    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.pause()
        table = app.screen.query_one("#results", DataTable)
        assert table.get_cell_at(Coordinate(0, 1)).plain.strip().startswith("█ ")
        await pilot.press("b")
        await pilot.pause()
        table = app.screen.query_one("#results", DataTable)
        assert risk_bar(95) in table.get_cell_at(Coordinate(0, 1)).plain


# ── the state that used to vanish with the toast ────────────────────────


@pytest.mark.asyncio
async def test_status_bar_keeps_the_active_filter_on_screen(report: ScanReport) -> None:
    """A toast said this and then disappeared while still filtering."""
    app = OtaconTUI(report)
    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.pause()
        status = app.screen.query_one("#statusbar", Static)
        assert "all levels" in status.render().plain
        await pilot.press("1")
        await pilot.pause()
        text = app.screen.query_one("#statusbar", Static).render().plain
        assert "CRIT only" in text
        assert "1 of 4 registered" in text


@pytest.mark.asyncio
async def test_status_bar_points_at_the_help_overlay(report: ScanReport) -> None:
    app = OtaconTUI(report)
    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.pause()
        assert "? for help" in app.screen.query_one("#statusbar", Static).render().plain


# ── the glossary the console never had ──────────────────────────────────


@pytest.mark.asyncio
async def test_help_overlay_explains_every_flag_and_band(report: ScanReport) -> None:
    """Four characters in a table cell are not an explanation on their own."""
    app = OtaconTUI(report)
    # Tall enough that the whole glossary is on screen: the assertion is that a
    # reader can see it, so anything scrolled out would rightly fail here.
    async with app.run_test(size=(150, 110)) as pilot:
        await pilot.pause()
        await pilot.press("question_mark")
        await pilot.pause()
        panel = app.screen.query_one("#help", Static)
        assert panel.has_class("visible")
        rendered = _screen_text(app)
    for term in FLAGS.values():
        assert term.short in rendered
    for level, span, _why in BANDS:
        assert span in rendered, level


@pytest.mark.asyncio
async def test_escape_closes_the_help_overlay(report: ScanReport) -> None:
    app = OtaconTUI(report)
    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.pause()
        await pilot.press("question_mark")
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        assert not app.screen.query_one("#help", Static).has_class("visible")


# ── the dossier's alignment bug ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_dossier_keeps_long_values_in_their_own_column(report: ScanReport) -> None:
    """A flat Text wrapped long values back to column zero.

    That broke the label/value grid on exactly the rows carrying the most
    evidence — IP lists and redirect URLs — so the pane is a real grid now.
    """
    long_ips = ["203.0.113.10", "203.0.113.11", "2a06:98c1:3120::b", "198.51.100.77"]
    report.results[0] = report.results[0].model_copy(update={"ip_addresses": long_ips})
    app = OtaconTUI(report)
    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.pause()
        lines = _screen_text(app).splitlines()
    label_line = next(i for i, line in enumerate(lines) if "Online" in line)
    # The label owns the left column; the value and its continuation are indented
    # past it rather than starting at the margin.
    for continuation in lines[label_line + 1 : label_line + 3]:
        if continuation.strip():
            assert continuation.startswith(" " * 4), continuation


@pytest.mark.asyncio
async def test_dossier_offers_actions_for_the_selected_row(report: ScanReport) -> None:
    """The pane's lower half was dead space on a short evidence list."""
    app = OtaconTUI(report)
    async with app.run_test(size=(150, 60)) as pilot:
        await pilot.pause()
        body = _screen_text(app)
    assert "WHAT YOU CAN DO" in body
    # A critical row is worth a takedown notice; the offer says so in words.
    assert "abuse notice" in body
