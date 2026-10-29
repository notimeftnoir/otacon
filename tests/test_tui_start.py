"""Tests for the opening screen: target entry, options, and scan memory."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from textual.geometry import Region
from textual.screen import Screen
from textual.widgets import Checkbox, Input, OptionList, Static

from otacon import history
from otacon.core.models import DomainResult, ScanReport
from otacon.core.types import PermutationType, RiskLevel, ScanPhase
from otacon.engine.progress import ScanProgress
from otacon.tui.app import OtaconTUI
from otacon.tui.screens import OverviewScreen, ResultsScreen, StartScreen
from otacon.ui.copy import PHASES


def _stored(target: str = "example.com") -> ScanReport:
    report = ScanReport(
        target=target,
        started_at=datetime(2026, 10, 28, 9, 30, tzinfo=UTC),
        total_permutations=239,
        results=[
            DomainResult(
                domain="examp1e.com",
                kind=PermutationType.HOMOGLYPH,
                resolves=True,
                ip_addresses=["1.2.3.4"],
                risk_score=95,
                risk_level=RiskLevel.CRITICAL,
            )
        ],
    )
    history.save(report)
    return report


# Attributes the screens set in __init__. A name already used by Textual would be
# overwritten by the framework at runtime: `_running` belongs to MessagePump and
# is set True once a screen starts, so a screen keeping its own flag there reads
# back True forever and every guard on it silently stops working.
_SCREEN_OWN_ATTRS = {
    StartScreen: {"_scanning", "_started", "_stop", "_hits"},
    ResultsScreen: {
        "_report",
        "_level",
        "_query",
        "_show_unregistered",
        "_rows",
        "_allowed",
        "_open_armed",
        "_focus_mode",
        "_bars",
        "_labelled_tally",
        "_sort",
        "_selected",
        "_armed",
    },
    OverviewScreen: {"_report", "_delta"},
}


def _render(app: OtaconTUI, widget: Static) -> str:
    """A widget's rendered text, for asserting on what the operator can read."""
    return "\n".join(
        "".join(segment.text for segment in strip)
        for strip in widget.render_lines(Region(0, 0, 80, 12))
    )


def _build(screen_cls: type) -> Screen:  # type: ignore[type-arg]
    """A screen instance, supplying the report the two result screens need."""
    return screen_cls() if screen_cls is StartScreen else screen_cls(_stored())


@pytest.mark.parametrize("screen_cls", list(_SCREEN_OWN_ATTRS))
def test_screens_do_not_shadow_textual_internals(screen_cls: type) -> None:
    framework = set(vars(Screen()))
    clashes = sorted(_SCREEN_OWN_ATTRS[screen_cls] & framework)
    assert not clashes, f"{screen_cls.__name__} shadows Textual internals: {clashes}"


@pytest.mark.parametrize("screen_cls", list(_SCREEN_OWN_ATTRS))
def test_the_declared_attribute_list_matches_reality(screen_cls: type) -> None:
    """Keeps the guard above honest when a screen gains an attribute.

    This used to check StartScreen alone, so the three attributes the results
    screen picked up when it learned focus mode and the bar toggle went
    unguarded — the guard was passing while covering less than it claimed.
    """
    declared = _SCREEN_OWN_ATTRS[screen_cls]
    actual = set(vars(_build(screen_cls))) - set(vars(Screen()))
    assert declared == actual, f"update _SCREEN_OWN_ATTRS[{screen_cls.__name__}]: {sorted(actual)}"


@pytest.mark.asyncio
async def test_opens_on_the_start_screen_without_a_report() -> None:
    app = OtaconTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert isinstance(app.screen, StartScreen)


@pytest.mark.asyncio
async def test_opens_on_the_overview_when_given_a_report() -> None:
    """The verdict comes first; the table is one keypress away."""
    app = OtaconTUI(_stored())
    async with app.run_test() as pilot:
        await pilot.pause()
        assert isinstance(app.screen, OverviewScreen)
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, ResultsScreen)


@pytest.mark.asyncio
async def test_empty_target_is_refused_without_scanning() -> None:
    app = OtaconTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, StartScreen)
        screen.action_start()
        await pilot.pause()
        assert screen._scanning is False
        assert isinstance(app.screen, StartScreen)


@pytest.mark.asyncio
async def test_an_invalid_target_is_refused_without_scanning() -> None:
    app = OtaconTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, StartScreen)
        screen.query_one("#target", Input).value = "not a domain!"
        screen.action_start()
        await pilot.pause()
        assert screen._scanning is False
        assert isinstance(app.screen, StartScreen)


@pytest.mark.asyncio
async def test_every_scan_option_is_on_by_default() -> None:
    app = OtaconTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        boxes = app.screen.query(Checkbox)
        assert len(boxes) == 4
        assert all(box.value for box in boxes)


@pytest.mark.asyncio
async def test_recent_list_is_hidden_when_nothing_is_stored() -> None:
    app = OtaconTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.screen.query_one("#recent", OptionList).display is False


@pytest.mark.asyncio
async def test_a_stored_scan_is_listed_and_reopens_offline() -> None:
    """Selecting a past scan must reach the results without touching the network."""
    _stored()
    app = OtaconTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        recent = app.screen.query_one("#recent", OptionList)
        assert recent.display is True
        assert recent.option_count == 1

        recent.focus()
        await pilot.press("down")
        await pilot.pause()
        await pilot.press("enter")
        for _ in range(4):
            await pilot.pause()

        # A reopened scan lands on its verdict like a fresh one does.
        assert isinstance(app.screen, OverviewScreen)
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, ResultsScreen)
        assert app.screen.selected is not None
        assert app.screen.selected.domain == "examp1e.com"


@pytest.mark.asyncio
async def test_a_deleted_stored_scan_reports_rather_than_crashing() -> None:
    report = _stored()
    record = history.scans(report.target)[0]
    record.path.unlink()

    app = OtaconTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        recent = app.screen.query_one("#recent", OptionList)
        if recent.option_count:
            recent.focus()
            await pilot.press("down")
            await pilot.press("enter")
            await pilot.pause()
        # Still on the form, and still usable.
        assert isinstance(app.screen, StartScreen)


# ── the scan while it runs ──────────────────────────────────────────────


def _progress(phase: ScanPhase, **kw: object) -> ScanProgress:
    return ScanProgress(phase=phase, **kw)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_each_stage_says_what_it_is_doing() -> None:
    """Certificate Transparency is one slow call before the counter can move.

    With nothing reported for it, a scan sat on a motionless bar for seconds
    and looked hung rather than busy.
    """
    app = OtaconTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, StartScreen)
        status = screen.query_one("#setup-status", Static)
        for phase in ScanPhase:
            screen._on_progress(_progress(phase, total=240, done=10))
            await pilot.pause()
            assert PHASES[phase] in status.render().plain


@pytest.mark.asyncio
async def test_findings_appear_while_the_scan_is_still_running() -> None:
    """`otacon scan` has always shown this; the console showed a bar."""
    app = OtaconTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, StartScreen)
        feed = screen.query_one("#scan-feed", Static)
        assert feed.display is False

        hit = DomainResult(
            domain="evil.com",
            kind=PermutationType.TYPO,
            resolves=True,
            ip_addresses=["1.2.3.4"],
            risk_score=90,
            risk_level=RiskLevel.CRITICAL,
            has_login_form=True,
        )
        screen._on_progress(
            _progress(ScanPhase.CHECKING, total=240, done=12, hits=1, dangerous=1, latest=hit)
        )
        await pilot.pause()
        assert feed.display is True
        assert "evil.com" in _render(app, feed)


@pytest.mark.asyncio
async def test_a_failing_resolver_is_reported_while_it_fails() -> None:
    """Saying it only in the verdict means watching a scan report nothing and
    believing the brand is clean for the whole minute it takes."""
    app = OtaconTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, StartScreen)
        screen._on_progress(
            _progress(ScanPhase.CHECKING, total=240, done=60, dns_queries=120, dns_failures=96)
        )
        await pilot.pause()
        assert "80% of DNS lookups are failing" in (
            screen.query_one("#setup-status", Static).render().plain
        )


@pytest.mark.asyncio
async def test_escape_stops_a_running_scan_without_tearing_it_down() -> None:
    app = OtaconTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, StartScreen)
        assert screen._should_stop() is False
        # Esc is inert until a scan is actually running.
        await pilot.press("escape")
        assert screen._should_stop() is False

        screen._scanning = True
        screen.action_stop_scan()
        assert screen._should_stop() is True
        assert "Stopping" in screen.query_one("#setup-status", Static).render().plain
