"""The screen a scan lands on: what it found, what changed, what to do first.

A scan of a real brand returns a few hundred permutations of which a handful
matter. Dropping straight into that table is fine for someone who already
knows what a combosquat is; for everybody else it is a wall.

So the console now opens on the answer. `otacon scan` has always printed a
verdict card and the triage console printed none of it, even though plain
`otacon` opens the console and not the scan — the surface most people meet
was the one giving least guidance. The wording here is the same
`triage.verdict` the card uses, not a second copy.

Enter moves on to the table for anyone who wants the full set.
"""

from __future__ import annotations

from typing import ClassVar

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Static

from ...core.models import ScanReport
from ...core.types import RiskLevel
from ...net.whois import format_age
from ...triage.verdict import Delta, reasons, verdict, worst_first
from ...ui.tokens import Palette
from ...utils.theme import active_palette, glyph
from ..widgets import distribution, wordmark
from .results import ResultsScreen

_TONE_LEVEL = {
    "danger": RiskLevel.HIGH,
    "warn": RiskLevel.MEDIUM,
    "ok": RiskLevel.SAFE,
}


class OverviewScreen(Screen[None]):
    """The verdict, what changed since last time, and the first three moves."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        # key_display: Textual renders "enter" as U+23CE, which is outside the
        # font budget in ui.glyphs and shows as tofu in Courier New.
        Binding("enter", "open_table", "all findings", key_display="enter"),
        Binding("c", "compare", "compare"),
        Binding("comma", "settings", "settings", show=False),
        Binding("q", "app.quit", "quit"),
    ]

    def __init__(self, report: ScanReport, change: Delta | None = None) -> None:
        super().__init__()
        self._report = report
        self._delta = change

    @property
    def palette(self) -> Palette:
        """The palette this screen draws with."""
        app_palette = getattr(self.app, "ui_palette", None)
        return app_palette if isinstance(app_palette, Palette) else active_palette()

    def compose(self) -> ComposeResult:
        with Horizontal(id="masthead"):
            yield Static(self._brand_text(), id="brand")
            yield Static(self._meta_text(), id="tally")
        yield VerticalScroll(Static(self._body(), id="overview-body"), id="overview")
        yield Footer()

    def _brand_text(self) -> Text:
        pal = self.palette
        t = Text(" ")
        t.append_text(wordmark(palette=pal))
        t.append(glyph(" › "), style=pal.line_strong)  # noqa: RUF001  — separator, not ">"
        t.append(self._report.target, style=f"bold {pal.strong}")
        return t

    def _meta_text(self) -> Text:
        pal = self.palette
        t = Text()
        t.append(f"{self._report.total_permutations} checked ", style=pal.muted)
        return t

    def _grid(self, label_width: int = 20) -> Table:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(width=label_width, no_wrap=True)
        grid.add_column(ratio=1, overflow="fold")
        return grid

    def _body(self) -> RenderableType:
        pal = self.palette
        v = verdict(self._report)
        tone = pal.tone(_TONE_LEVEL[v.tone])

        marker = glyph(v.marker)
        parts: list[RenderableType] = [
            Text(f"{marker} {v.headline}", style=f"bold {tone.fg}"),
            Text(v.explanation, style=pal.muted),
        ]

        if self._report.registered:
            parts += [Text(""), distribution(self._report, palette=pal)]

        if self._delta is not None and not self._delta.quiet:
            days = max((self._report.started_at - self._delta.since).days, 0)
            when = "earlier today" if days < 1 else f"{format_age(days)} ago"
            parts.append(
                Text(glyph(f"\nSINCE YOUR LAST SCAN · {when}"), style=f"bold {pal.brand_dim}")
            )
            changed = self._grid()
            for change in self._delta.changes[:6]:
                changed.add_row(
                    Text(change.domain, style=f"bold {pal.strong}"),
                    Text(change.detail, style=pal.muted),
                )
            parts.append(changed)
            if len(self._delta.changes) > 6:
                rest = len(self._delta.changes) - 6
                parts.append(Text(f"  and {rest} more", style=pal.dim))

        top = worst_first(self._report)
        if top:
            parts.append(Text("\nWHAT TO DO FIRST", style=f"bold {pal.brand_dim}"))
            steps = Table.grid(padding=(0, 2))
            steps.add_column(width=2, no_wrap=True)
            steps.add_column(width=24, no_wrap=True)
            steps.add_column(ratio=1, overflow="fold")
            for i, r in enumerate(top, start=1):
                level = pal.tone(r.risk_level)
                steps.add_row(
                    Text(str(i), style=pal.dim),
                    Text(r.domain, style=f"bold {level.fg}"),
                    Text(reasons(r), style=pal.muted),
                )
            parts.append(steps)

        parts.append(Text(""))
        parts.append(self._hint())
        return Group(*parts)

    def _hint(self) -> Text:
        """The one instruction on the screen. Spelled out, not a bare key name."""
        pal = self.palette
        count = len(self._report.registered)
        t = Text()
        t.append("Press enter", style=f"bold {pal.brand}")
        if count:
            t.append(
                f" to work through all {count} registered lookalike{'s' if count != 1 else ''}.",
                style=pal.muted,
            )
        else:
            t.append(" to see everything that was checked.", style=pal.muted)
        return t

    def action_settings(self) -> None:
        """Opens the settings, allow-list and watchlist for this target."""
        from .settings import SettingsScreen

        self.app.push_screen(SettingsScreen(self._report.target))

    def action_compare(self) -> None:
        """Opens the full comparison against the previous stored scan."""
        from .compare import CompareScreen

        self.app.push_screen(CompareScreen(self._report))

    def action_open_table(self) -> None:
        """Opens the full findings table.

        On a clean scan the table's default filter would leave it empty, so
        the unregistered variants are shown instead of nothing at all.
        """
        self.app.push_screen(
            ResultsScreen(self._report, show_unregistered=not self._report.registered)
        )


__all__ = ["OverviewScreen"]
