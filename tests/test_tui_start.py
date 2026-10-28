"""Tests for the opening screen: target entry, options, and scan memory."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from textual.screen import Screen
from textual.widgets import Checkbox, Input, OptionList

from otacon import history
from otacon.core.models import DomainResult, ScanReport
from otacon.core.types import PermutationType, RiskLevel
from otacon.tui.app import OtaconTUI
from otacon.tui.screens import ResultsScreen, StartScreen


@pytest.fixture(autouse=True)
def _isolated_history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Never touch the operator's real history while testing."""
    monkeypatch.setenv("OTACON_HOME", str(tmp_path))
    monkeypatch.delenv("OTACON_NO_HISTORY", raising=False)


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
    StartScreen: {"_scanning", "_started"},
    ResultsScreen: {
        "_report",
        "_level",
        "_query",
        "_show_unregistered",
        "_rows",
        "_allowed",
        "_open_armed",
    },
}


@pytest.mark.parametrize("screen_cls", list(_SCREEN_OWN_ATTRS))
def test_screens_do_not_shadow_textual_internals(screen_cls: type) -> None:
    framework = set(vars(Screen()))
    clashes = sorted(_SCREEN_OWN_ATTRS[screen_cls] & framework)
    assert not clashes, f"{screen_cls.__name__} shadows Textual internals: {clashes}"


def test_the_declared_attribute_list_matches_reality() -> None:
    """Keeps the guard above honest if a screen gains an attribute."""
    declared = _SCREEN_OWN_ATTRS[StartScreen]
    actual = set(vars(StartScreen())) - set(vars(Screen()))
    assert declared == actual, f"update _SCREEN_OWN_ATTRS: {sorted(actual)}"


@pytest.mark.asyncio
async def test_opens_on_the_start_screen_without_a_report() -> None:
    app = OtaconTUI()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert isinstance(app.screen, StartScreen)


@pytest.mark.asyncio
async def test_opens_on_results_when_given_a_report() -> None:
    app = OtaconTUI(_stored())
    async with app.run_test() as pilot:
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
