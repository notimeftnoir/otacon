"""The Otacon triage console.

Launched bare, it opens on the start screen: name a target, pick how deep to
look, and the scan runs inside the application. Given a report — from
`otacon tui <domain>` or `--from report.json` — it opens straight on the
results.

The screens hold the behaviour; this module only decides which one opens and
carries the stylesheet.
"""

from __future__ import annotations

from ..core.models import ScanReport
from .screens import ResultsScreen, StartScreen
from .styles import OTACON_CSS

from textual.app import App  # isort: skip


class OtaconTUI(App[None]):
    """Keyboard-driven triage console."""

    CSS = OTACON_CSS
    TITLE = "OTACON"

    def __init__(self, report: ScanReport | None = None) -> None:
        super().__init__()
        self._report = report

    def on_mount(self) -> None:
        """Opens on the results when a report was supplied, otherwise on the form."""
        if self._report is None:
            self.push_screen(StartScreen())
        else:
            self.push_screen(ResultsScreen(self._report))


def run_tui(report: ScanReport | None = None) -> None:
    """Opens the triage console. Returns when the operator quits."""
    OtaconTUI(report).run()


__all__ = ["OtaconTUI", "run_tui"]
