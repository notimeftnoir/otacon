"""What changed since the last scan of this target.

A lookalike that appeared this week matters more than one parked for years,
and the only way to tell them apart is to have looked before. Otacon has
looked before — every scan is stored — but the comparison was only ever shown
in one place: the overview of a scan that had just finished. Reopening a saved
report, or walking back from the table, lost it.

Nothing here re-computes anything. `triage.verdict.baseline` picks the stored
run to compare against and `triage.verdict.delta` says what moved; this groups
the result so the three questions a reader actually has — what is new, what
got worse, what went away — are three headings rather than one list.
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

from ...core.models import DomainResult, ScanReport
from ...net.whois import format_age
from ...triage.verdict import Change, ChangeKind, baseline, delta
from ...ui.tokens import Palette
from ...utils.theme import active_palette, glyph
from ..widgets import badges, sigil, wordmark

# Worst news first. "Gone" is last because a lookalike that stopped resolving
# is the one kind of change nobody has to act on.
_SECTIONS: tuple[tuple[ChangeKind, str], ...] = (
    (ChangeKind.REGISTERED, "NEWLY REGISTERED"),
    (ChangeKind.ESCALATED, "GOT WORSE"),
    (ChangeKind.FOUND, "NEW TO THIS SCAN"),
    (ChangeKind.GONE, "NO LONGER REGISTERED"),
)


class CompareScreen(Screen[None]):
    """The current scan against the previous stored one."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "app.pop_screen", "back"),
        Binding("c", "app.pop_screen", "back", show=False),
        Binding("q", "app.quit", "quit"),
    ]

    def __init__(self, report: ScanReport, previous: ScanReport | None = None) -> None:
        super().__init__()
        self._report = report
        self._previous = previous if previous is not None else baseline(report)

    @property
    def palette(self) -> Palette:
        """The palette this screen draws with."""
        app_palette = getattr(self.app, "ui_palette", None)
        return app_palette if isinstance(app_palette, Palette) else active_palette()

    def compose(self) -> ComposeResult:
        with Horizontal(id="masthead"):
            yield Static(self._brand_text(), id="brand")
            yield Static(self._meta_text(), id="tally")
        yield VerticalScroll(Static(self._body(), id="compare-body"), id="compare")
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
        if self._previous is None:
            return Text("no earlier scan ", style=pal.muted)
        days = max((self._report.started_at - self._previous.started_at).days, 0)
        when = "earlier today" if days < 1 else f"{glyph(format_age(days))} ago"
        return Text(f"compared with {when} ", style=pal.muted)

    def _by_domain(self) -> dict[str, DomainResult]:
        return {r.domain: r for r in self._report.results}

    def _body(self) -> RenderableType:
        pal = self.palette
        if self._previous is None:
            return Group(
                Text("\nThis is the first scan of this target.", style=f"bold {pal.strong}"),
                Text(
                    "Run it again in a week and this screen will show what moved: "
                    "which lookalikes were registered since, which got worse, and "
                    "which stopped resolving.",
                    style=pal.muted,
                ),
            )

        change = delta(self._previous, self._report)
        if change.quiet:
            return Group(
                Text("\nNothing moved.", style=f"bold {pal.strong}"),
                Text(
                    "No lookalike was registered, got worse or went away since the "
                    "last scan. That is the result you want, and it is worth having "
                    "asked.",
                    style=pal.muted,
                ),
            )

        rows = self._by_domain()
        parts: list[RenderableType] = []
        for kind, heading in _SECTIONS:
            group = [c for c in change.changes if c.kind is kind]
            if not group:
                continue
            parts.append(Text(f"\n{heading}  {len(group)}", style=f"bold {pal.brand_dim}"))
            parts.append(self._section(group, rows))
        return Group(*parts)

    def _section(self, group: list[Change], rows: dict[str, DomainResult]) -> Table:
        """One heading's worth of changes, with the row's current state beside it."""
        pal = self.palette
        grid = Table.grid(padding=(0, 2))
        grid.add_column(width=5, no_wrap=True)
        grid.add_column(width=30, no_wrap=True)
        grid.add_column(ratio=1, overflow="fold")
        for item in group:
            current = rows.get(item.domain)
            if current is None:
                # Present in the earlier scan and absent from this one.
                mark = Text("")
                trailing = Text(item.detail, style=pal.dim)
            else:
                tone = pal.tone(current.risk_level)
                mark = Text(sigil(current.risk_level, pal), style=tone.fg)
                mark.append(f" {current.risk_score:>3}", style=tone.fg)
                flags = badges(current)
                trailing = Text(flags or item.detail, style=tone.fg if flags else pal.muted)
            grid.add_row(mark, Text(item.domain, style=f"bold {pal.strong}"), trailing)
        return grid


__all__ = ["CompareScreen"]
