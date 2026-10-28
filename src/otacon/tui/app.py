"""The Otacon triage console.

Launched bare, it opens on the start screen: name a target, pick how deep to
look, and the scan runs inside the application. Given a report — from
`otacon tui <domain>` or `--from report.json` — it opens straight on the
results.

The screens hold the behaviour; this module only decides which one opens,
carries the stylesheet, and feeds the active palette into Textual as design
tokens so the stylesheet needs no colours of its own.
"""

from __future__ import annotations

from typing import Literal

from ..core.models import ScanReport
from ..ui.emit import textual_vars
from ..ui.tokens import Palette
from ..utils.theme import active_palette
from .screens import OverviewScreen, ResultsScreen, StartScreen
from .styles import OTACON_CSS

from textual.app import App  # isort: skip

Landing = Literal["overview", "results"]
"""Which screen a report opens on. ``overview`` answers "am I in trouble" first."""


class OtaconTUI(App[None]):
    """Keyboard-driven triage console."""

    CSS = OTACON_CSS
    TITLE = "OTACON"

    def __init__(
        self,
        report: ScanReport | None = None,
        palette: Palette | None = None,
        landing: Landing = "overview",
    ) -> None:
        # Set before super().__init__, which builds the stylesheet and so calls
        # get_css_variables() while this object is still half-constructed.
        # Captured once rather than read per lookup: Textual resolves CSS
        # variables at startup, so a palette swapped afterwards would leave the
        # stylesheet and the widgets disagreeing.
        self.ui_palette = palette or active_palette()
        super().__init__()
        self._report = report
        self._landing = landing

    def get_css_variables(self) -> dict[str, str]:
        """Adds the Otacon design tokens to Textual's own CSS variables."""
        return {**super().get_css_variables(), **textual_vars(self.ui_palette)}

    def on_mount(self) -> None:
        """Opens on the overview when a report was supplied, otherwise on the form."""
        if self._report is None:
            self.push_screen(StartScreen())
        elif self._landing == "results":
            self.push_screen(ResultsScreen(self._report))
        else:
            self.push_screen(OverviewScreen(self._report))


def run_tui(
    report: ScanReport | None = None,
    palette: Palette | None = None,
    landing: Landing = "overview",
) -> None:
    """Opens the triage console. Returns when the operator quits."""
    OtaconTUI(report, palette, landing).run()


__all__ = ["Landing", "OtaconTUI", "run_tui"]
