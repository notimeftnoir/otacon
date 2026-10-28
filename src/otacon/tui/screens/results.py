"""The triage screen: a filterable table of findings beside their evidence.

A scan produces a few hundred rows of which a handful matter. This keeps the
whole report in memory and lets one hand work it: move with the arrows, cut the
set down with a digit, read the evidence for the row under the cursor in the
pane beside it, and act on it in place.

Nothing here re-implements analysis. Rows come from a ScanReport that engine and
scoring already produced, the evidence pane renders triage.dossier.evidence, the
abuse notice comes from triage.notice.build_takedown_notice, and a re-check goes
through triage.actions.rescan_result.
"""

from __future__ import annotations

import webbrowser
from pathlib import Path
from typing import ClassVar
from urllib.parse import quote

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import Resize
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Input, Static

from ...core.models import DomainResult, ScanReport
from ...core.types import RiskLevel
from ...net.whois import fetch_domain_age, format_age
from ...reporters.json import to_json
from ...triage.actions import rescan_result
from ...triage.dossier import evidence
from ...triage.notice import build_takedown_notice
from ...ui.copy import BANDS, FLAGS, TECHNIQUES
from ...ui.tokens import Palette
from ...utils.theme import active_palette
from ...utils.validate import safe_relative_path
from ..widgets import (
    BAR_WIDTH,
    FILTER_KEYS,
    LEVELS_DESC,
    badges,
    band_cell,
    gutter,
    level_color,
    risk_bar,
    signals,
    tally,
    wordmark,
)

# Below this the labelled tally (CRIT 0  HIGH 2 …) no longer fits beside the
# target name, so it falls back to the glyph ramp.
_LABELLED_TALLY_WIDTH = 96

_LABEL_WIDTH = 13


class ResultsScreen(Screen[None]):
    """Table of findings on the right, dossier for the current row on the left."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("q", "app.quit", "quit"),
        Binding("question_mark", "help", "help"),
        Binding("escape", "clear_filter", "clear", show=False),
        Binding("slash", "search", "search"),
        Binding("0", "filter_all", "all", show=False),
        Binding("1", "filter_level('1')", "crit"),
        Binding("2", "filter_level('2')", "high", show=False),
        Binding("3", "filter_level('3')", "med", show=False),
        Binding("4", "filter_level('4')", "low", show=False),
        Binding("5", "filter_level('5')", "safe", show=False),
        Binding("f", "toggle_focus", "focus"),
        Binding("b", "toggle_bars", "bars", show=False),
        Binding("u", "toggle_unregistered", "unreg", show=False),
        Binding("w", "whois", "whois", show=False),
        Binding("o", "open_site", "open"),
        Binding("t", "takedown", "takedown"),
        Binding("e", "export", "export", show=False),
        Binding("r", "rescan", "rescan", show=False),
        Binding("a", "allow", "allow", show=False),
        Binding("j", "cursor_down", "down", show=False),
        Binding("k", "cursor_up", "up", show=False),
    ]

    def __init__(self, report: ScanReport) -> None:
        super().__init__()
        self._report = report
        self._level: RiskLevel | None = None
        self._query = ""
        self._show_unregistered = False
        self._rows: list[DomainResult] = []
        # Domains the operator has waved through for this session only. Never
        # written anywhere: an allow-list that outlives the session is a
        # decision for --exclude, not a keystroke.
        self._allowed: set[str] = set()
        self._open_armed: str | None = None
        self._focus_mode = False
        self._bars = False
        self._labelled_tally = True

    @property
    def palette(self) -> Palette:
        """The palette this screen draws with."""
        app_palette = getattr(self.app, "ui_palette", None)
        return app_palette if isinstance(app_palette, Palette) else active_palette()

    # ── layout ──────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        with Horizontal(id="masthead"):
            yield Static(self._brand_text(), id="brand")
            yield Static(self._tally_text(), id="tally")
        with Horizontal(id="body"):
            # Dossier on the left, results on the right: the operator reads the
            # evidence for the current row first and steers with the table second.
            yield VerticalScroll(Static("", id="dossier-body"), id="dossier")
            with Vertical(id="rail"):
                yield DataTable(id="results", cursor_type="row", zebra_stripes=False)
                yield Input(placeholder="filter domains…", id="filterbar")
        yield Static("", id="statusbar")
        yield Static("", id="notice")
        yield Static("", id="help")
        yield Footer()

    def on_mount(self) -> None:
        self._build_columns()
        self.refresh_rows()
        self.query_one("#results", DataTable).focus()

    def _build_columns(self) -> None:
        """Lays out the table. Called again when the risk column changes width.

        BAND names each severity run where it starts, and RISK carries one
        density glyph rather than an eight-cell bar: stacked down a real scan
        that bar painted a single uniform block, because the scores inside a
        band rarely differ by enough to change its length.
        """
        table = self.query_one("#results", DataTable)
        table.clear(columns=True)
        table.add_column("BAND", width=4)
        table.add_column("RISK", width=(BAR_WIDTH + 4) if self._bars else 5)
        # Widths are tuned so FLAGS — the column that changes what an operator
        # does with a row — still fits inside the rail on a narrow terminal.
        table.add_column("DOMAIN", width=28)
        table.add_column("TECH", width=11)
        table.add_column("AGE", width=5)
        table.add_column("SIGNALS", width=15)
        table.add_column("FLAGS")

    def on_resize(self, _event: Resize) -> None:
        """Drops the tally to glyphs when the labels no longer fit."""
        labelled = self.size.width >= _LABELLED_TALLY_WIDTH
        if labelled != self._labelled_tally:
            self._labelled_tally = labelled
            self.query_one("#tally", Static).update(self._tally_text())

    # ── header ──────────────────────────────────────────────────────────

    def _brand_text(self) -> Text:
        pal = self.palette
        t = Text(" ")
        t.append_text(wordmark(palette=pal))
        t.append(" › ", style=pal.line_strong)  # noqa: RUF001  — UI separator, not ">"
        t.append(self._report.target, style=f"bold {pal.strong}")
        return t

    def _tally_text(self) -> Text:
        return tally(self._report, labelled=self._labelled_tally, palette=self.palette)

    # ── row set ─────────────────────────────────────────────────────────

    def _visible(self) -> list[DomainResult]:
        rows = [
            r
            for r in self._report.results
            if (self._show_unregistered or r.is_registered) and r.domain not in self._allowed
        ]
        if self._level is not None:
            rows = [r for r in rows if r.risk_level == self._level]
        if self._query:
            needle = self._query.lower()
            rows = [r for r in rows if needle in r.domain.lower()]
        return sorted(rows, key=lambda r: (-r.risk_score, r.domain))

    def _focus_floor(self) -> RiskLevel | None:
        """The worst band that actually has rows, or None when nothing is shown.

        Focus mode dims everything below it. On a typical scan — two high rows
        under thirty-seven medium ones — that is the whole point: the rows worth
        acting on stop competing with the rest for attention.
        """
        for level in LEVELS_DESC:
            if any(r.risk_level == level for r in self._rows):
                return level
        return None

    def refresh_rows(self) -> None:
        """Rebuilds the table from the report under the current filters."""
        table = self.query_one("#results", DataTable)
        table.clear()
        self._rows = self._visible()
        pal = self.palette
        floor = self._focus_floor() if self._focus_mode else None
        previous: RiskLevel | None = None
        for r in self._rows:
            dimmed = floor is not None and r.risk_level.rank < floor.rank
            colour = pal.dim if dimmed else level_color(r.risk_level, pal)
            muted = pal.dim if dimmed else pal.muted
            mark = (
                Text(risk_bar(r.risk_score), style=colour)
                if self._bars
                else gutter(r.risk_level, pal)
            )
            score = Text()
            score.append_text(mark)
            score.append(f" {r.risk_score:>3}", style=colour)
            table.add_row(
                band_cell(r.risk_level, r.risk_level != previous, pal),
                score,
                Text(r.domain, style=pal.dim if dimmed else f"bold {pal.strong}"),
                Text(r.kind.value, style=pal.dim if dimmed else pal.brand_dim),
                Text(format_age(r.age_days), style=muted),
                Text(signals(r), style=muted),
                Text(badges(r), style=colour),
            )
            previous = r.risk_level
        self.query_one("#tally", Static).update(self._tally_text())
        self._render_status()
        self._render_dossier()

    @property
    def selected(self) -> DomainResult | None:
        """The row under the cursor, or None when the filter matches nothing."""
        table = self.query_one("#results", DataTable)
        if not self._rows or table.cursor_row < 0 or table.cursor_row >= len(self._rows):
            return None
        return self._rows[table.cursor_row]

    # ── status bar ──────────────────────────────────────────────────────

    def _render_status(self) -> None:
        """Keeps the view's state on screen.

        This was previously carried by toasts, which meant the active filter
        became invisible two seconds after it was applied while still filtering.
        """
        pal = self.palette
        shown = len(self._rows)
        total = sum(1 for r in self._report.results if r.is_registered)
        t = Text()
        if self._level is not None:
            band = pal.tone(self._level).band
            t.append(f"{band} only", style=f"bold {level_color(self._level, pal)}")
        else:
            t.append("all levels", style=pal.muted)
        t.append("  ·  ", style=pal.line_strong)
        t.append(f"{shown} of {total} registered", style=pal.muted)
        if self._show_unregistered:
            t.append(" + unregistered", style=pal.muted)
        if self._query:
            t.append("  ·  ", style=pal.line_strong)
            t.append(f"matching {self._query!r}", style=pal.accent)
        if self._focus_mode:
            floor = self._focus_floor()
            t.append("  ·  ", style=pal.line_strong)
            t.append(
                f"focus: {pal.tone(floor).band}" if floor else "focus",
                style=f"bold {pal.brand}",
            )
        if self._allowed:
            t.append("  ·  ", style=pal.line_strong)
            t.append(f"{len(self._allowed)} allowed", style=pal.muted)
        t.append("   ? for help", style=pal.dim)
        self.query_one("#statusbar", Static).update(t)

    # ── dossier ─────────────────────────────────────────────────────────

    def _kv_grid(self) -> Table:
        """Two-column grid for label/value pairs.

        The dossier used to be one flat Text, so a long value — a list of IP
        addresses, a redirect URL — wrapped back to column zero and broke the
        alignment on exactly the rows that carry the most evidence. A grid
        folds the value under itself instead.
        """
        grid = Table.grid(padding=(0, 1))
        grid.add_column(width=_LABEL_WIDTH, no_wrap=True)
        grid.add_column(ratio=1, overflow="fold")
        return grid

    def _render_dossier(self) -> None:
        body = self.query_one("#dossier-body", Static)
        r = self.selected
        pal = self.palette
        if r is None:
            body.update(
                Text("no rows match the current filter", style=pal.dim)
                if self._rows == []
                else Text("")
            )
            return

        tone = pal.tone(r.risk_level)
        head = Text()
        head.append(f"{r.domain}\n", style=f"bold {pal.strong}")
        head.append(f"{tone.sigil} {r.risk_level.value.upper()} ", style=tone.fg)
        head.append(f"{r.risk_score}/100", style=f"bold {pal.strong}")
        head.append(f"  {tone.label}", style=pal.muted)
        head.append(f"\n{TECHNIQUES[r.kind].long}", style=pal.brand_dim)
        if r.note:
            head.append(f" · {r.note}", style=pal.muted)
        head.append("\n")
        head.append("─" * 40, style=pal.line)

        parts: list[RenderableType] = [head]

        rows = evidence(r)
        if rows:
            parts.append(Text("\nEVIDENCE", style=f"bold {pal.brand_dim}"))
            grid = self._kv_grid()
            for label, fact, meaning in rows:
                grid.add_row(Text(label, style=f"bold {pal.body}"), Text(fact, style=pal.strong))
                grid.add_row(Text(""), Text(meaning, style=pal.dim))
            parts.append(grid)
        else:
            parts.append(Text("\nregistered, but nothing is running", style=pal.dim))

        if r.risk_reasons:
            parts.append(Text("\nSCORING", style=f"bold {pal.brand_dim}"))
            reasons = self._kv_grid()
            for reason in r.risk_reasons:
                reasons.add_row(Text("·", style=pal.line_strong), Text(reason, style=pal.muted))
            parts.append(reasons)

        # The pane's lower half used to be dead space on a short evidence list.
        parts.append(Text("\nWHAT YOU CAN DO", style=f"bold {pal.brand_dim}"))
        actions = self._kv_grid()
        for key, what in self._actions_for(r):
            actions.add_row(Text(key, style=f"bold {pal.brand}"), Text(what, style=pal.muted))
        parts.append(actions)

        body.update(Group(*parts))

    def _actions_for(self, r: DomainResult) -> list[tuple[str, str]]:
        """The keys worth pressing on this row, in the order worth pressing them."""
        out: list[tuple[str, str]] = []
        if r.risk_level.rank >= RiskLevel.HIGH.rank:
            out.append(("t", "write an abuse notice to its registrar"))
        out.append(("o", "look at the site safely (warns first)"))
        if r.age_days is None:
            out.append(("w", "find out when it was registered"))
        out.append(("r", "check it again right now"))
        out.append(("e", "export this one row as JSON"))
        if r.is_likely_defensive:
            out.append(("a", "it is yours — hide it for this session"))
        return out

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        # Moving off a row disarms a pending browser open, so `o` never fires
        # against a domain other than the one the warning named.
        self._open_armed = None
        self._render_dossier()

    # ── navigation ──────────────────────────────────────────────────────

    def action_cursor_down(self) -> None:
        """Moves the row cursor down, for vi-style `j`."""
        self.query_one("#results", DataTable).action_cursor_down()

    def action_cursor_up(self) -> None:
        """Moves the row cursor up, for vi-style `k`."""
        self.query_one("#results", DataTable).action_cursor_up()

    # ── view modes ──────────────────────────────────────────────────────

    def action_toggle_focus(self) -> None:
        """Dims every row below the worst band present."""
        self._focus_mode = not self._focus_mode
        self.refresh_rows()

    def action_toggle_bars(self) -> None:
        """Swaps the severity glyph for the full eight-cell bar, and back."""
        self._bars = not self._bars
        self._build_columns()
        self.refresh_rows()

    # ── filtering ───────────────────────────────────────────────────────

    def action_filter_level(self, key: str) -> None:
        """Restricts the table to one risk level, or lifts it if already active."""
        level = FILTER_KEYS[key]
        self._level = None if self._level == level else level
        self.refresh_rows()

    def action_filter_all(self) -> None:
        """Clears the level filter."""
        self._level = None
        self.refresh_rows()

    def action_toggle_unregistered(self) -> None:
        """Shows or hides variants that nobody has registered."""
        self._show_unregistered = not self._show_unregistered
        self.refresh_rows()

    def action_search(self) -> None:
        """Reveals the substring filter and focuses it."""
        bar = self.query_one("#filterbar", Input)
        bar.add_class("visible")
        bar.focus()

    def action_clear_filter(self) -> None:
        """Dismisses an overlay, or clears the search, or drops focus back."""
        for overlay_id in ("#help", "#notice"):
            overlay = self.query_one(overlay_id, Static)
            if overlay.has_class("visible"):
                overlay.remove_class("visible")
                self._open_armed = None
                return
        bar = self.query_one("#filterbar", Input)
        bar.value = ""
        bar.remove_class("visible")
        self._query = ""
        self.refresh_rows()
        self.query_one("#results", DataTable).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        self._query = event.value.strip()
        self.refresh_rows()

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self.query_one("#results", DataTable).focus()

    # ── help ────────────────────────────────────────────────────────────

    def action_help(self) -> None:
        """Explains the keys, the flags and the score, without leaving the row."""
        panel = self.query_one("#help", Static)
        if panel.has_class("visible"):
            panel.remove_class("visible")
            return
        panel.update(self._help_text())
        panel.add_class("visible")

    def _help_text(self) -> RenderableType:
        """The glossary the console never had.

        Every flag and every band is spelled out here because the table can
        only afford four characters for each, and a marker nobody can look up
        is a marker nobody can act on.
        """
        pal = self.palette
        parts: list[RenderableType] = [
            Text("OTACON — triage console\n", style=f"bold {pal.brand}"),
            Text(
                "Each row is a domain that looks like yours and is registered to "
                "someone. The score says how much it behaves like a real attack.",
                style=pal.muted,
            ),
            Text("\nKEYS", style=f"bold {pal.brand_dim}"),
        ]
        keys = self._kv_grid()
        for key, what in (
            ("↑ ↓  j k", "move between rows"),
            ("1 … 5", "show only one severity, press again to lift it"),
            ("0", "show every severity"),
            ("f", "dim everything below the worst band present"),
            ("b", "swap the severity glyph for a full bar"),
            ("u", "also show variants nobody registered"),
            ("/", "filter by part of a domain name"),
            ("w", "look up when the domain was registered"),
            ("o", "open the site — warns before it does"),
            ("t", "write an abuse notice for its registrar"),
            ("e", "export the selected row as JSON"),
            ("r", "re-check the selected row now"),
            ("a", "hide a row for this session"),
            ("esc", "close this, or clear the filter"),
            ("q", "quit"),
        ):
            keys.add_row(Text(key, style=f"bold {pal.brand}"), Text(what, style=pal.muted))
        parts.append(keys)

        parts.append(Text("\nWHAT THE SCORE MEANS", style=f"bold {pal.brand_dim}"))
        bands = self._kv_grid()
        for level, span, why in BANDS:
            tone = pal.tone(level)
            bands.add_row(
                Text(f"{tone.sigil} {tone.band} {span}", style=f"bold {tone.fg}"),
                Text(why, style=pal.muted),
            )
        parts.append(bands)

        parts.append(Text("\nFLAGS", style=f"bold {pal.brand_dim}"))
        flags = self._kv_grid()
        for term in FLAGS.values():
            flags.add_row(
                Text(term.short, style=f"bold {pal.body}"), Text(term.meaning, style=pal.muted)
            )
        parts.append(flags)

        parts.append(Text("\nHOW IT WAS FOUND", style=f"bold {pal.brand_dim}"))
        techs = self._kv_grid()
        for term in TECHNIQUES.values():
            techs.add_row(
                Text(term.short, style=f"bold {pal.body}"), Text(term.meaning, style=pal.muted)
            )
        parts.append(techs)
        parts.append(Text("\nPress ? or Esc to close.", style=pal.dim))
        return Group(*parts)

    # ── actions on the selected row ─────────────────────────────────────

    def action_allow(self) -> None:
        """Drops the selected domain from this session's view."""
        r = self.selected
        if r is None:
            return
        self._allowed.add(r.domain)
        self.refresh_rows()
        self.notify(f"allowed for this session: {r.domain}", timeout=4)

    def action_open_site(self) -> None:
        """Shows the OPSEC warning, then opens the site if `o` is pressed again.

        Visiting a live phishing page from your own browser leaks your address and
        fingerprint to the operator, so the first press only shows what you would
        be opening and offers the sandbox instead.
        """
        r = self.selected
        if r is None:
            return
        pal = self.palette
        notice = self.query_one("#notice", Static)
        if self._open_armed == r.domain:
            self._open_armed = None
            notice.remove_class("visible")
            webbrowser.open(f"https://{r.domain}")
            self.notify(f"opened {r.domain} in your browser", timeout=4)
            return

        self._open_armed = r.domain
        defanged = r.domain.replace(".", "[.]")
        warning = Text()
        warning.append("⚠  OPSEC warning\n\n", style=f"bold {pal.tone(RiskLevel.MEDIUM).fg}")
        warning.append(f"{r.domain} is rated {r.risk_level.value}. ", style=pal.body)
        warning.append(
            "Opening it in your own browser exposes your address and fingerprint "
            "to whoever runs it.\n\n",
            style=pal.body,
        )
        warning.append("Defanged IOC   ", style=f"bold {pal.body}")
        warning.append(f"hxxps://{defanged}\n", style=pal.strong)
        warning.append("Sandbox        ", style=f"bold {pal.body}")
        warning.append(f"https://urlscan.io/search/#{quote(r.domain)}\n\n", style=pal.accent)
        warning.append(
            "Press o again to open anyway, Esc to cancel.",
            style=f"bold {pal.tone(RiskLevel.HIGH).fg}",
        )
        notice.update(warning)
        notice.add_class("visible")

    def action_takedown(self) -> None:
        """Renders the abuse notice for the selected row and writes it to the cwd."""
        r = self.selected
        if r is None:
            return
        text = build_takedown_notice(r, self._report.target)
        notice = self.query_one("#notice", Static)
        notice.update(Text(text, style=self.palette.body))
        notice.add_class("visible")
        self._write_beside_cwd(f"takedown-{r.domain.replace('.', '_')}.txt", text, "notice saved")

    def action_export(self) -> None:
        """Writes the selected row as a single-result JSON report."""
        r = self.selected
        if r is None:
            return
        single = self._report.model_copy(update={"results": [r]})
        self._write_beside_cwd(f"{r.domain.replace('.', '_')}.json", to_json(single), "exported")

    def _write_beside_cwd(self, filename: str, body: str, verb: str) -> None:
        """Writes *body* to *filename* under the working directory, or reports why not.

        The filename is attacker-influenced — it is derived from a scanned domain —
        so it goes through the same containment check as the CLI's output paths
        rather than straight to open().
        """
        path = safe_relative_path(filename)
        if path is None:
            self.notify(f"refused unsafe filename: {filename}", severity="error", timeout=5)
            return
        try:
            Path(path).write_text(body, encoding="utf-8")
        except OSError as exc:
            self.notify(f"write failed: {exc}", severity="error", timeout=5)
            return
        self.notify(f"{verb}: {path}", timeout=4)

    def action_whois(self) -> None:
        """Fetches registration data for the selected row without blocking the UI."""
        r = self.selected
        if r is None:
            return
        if r.age_days is not None:
            self.notify(f"{r.domain}: registered {format_age(r.age_days)} ago", timeout=4)
            return
        self.notify(f"querying WHOIS for {r.domain}…", timeout=2)
        self.run_worker(self._do_whois(r.domain), exclusive=False)

    async def _do_whois(self, domain: str) -> None:
        created, age = await fetch_domain_age(domain)
        if created is None:
            self.notify(f"{domain}: no WHOIS data", severity="warning", timeout=4)
            return
        self._replace(domain, {"created_at": created, "age_days": age})
        self.notify(f"{domain}: registered {format_age(age)} ago", timeout=4)

    def action_rescan(self) -> None:
        """Re-probes the selected domain and rescores it in place."""
        r = self.selected
        if r is None:
            return
        self.notify(f"rescanning {r.domain}…", timeout=2)
        self.run_worker(self._do_rescan(r), exclusive=False)

    async def _do_rescan(self, result: DomainResult) -> None:
        try:
            updated = await rescan_result(result, self._report.target)
        except Exception as exc:
            self.notify(f"rescan failed: {exc}", severity="error", timeout=5)
            return
        for i, r in enumerate(self._report.results):
            if r.domain == updated.domain:
                self._report.results[i] = updated
                break
        self.refresh_rows()
        delta = updated.risk_score - result.risk_score
        move = f" ({delta:+d})" if delta else " (unchanged)"
        self.notify(f"{updated.domain}: {updated.risk_score}/100{move}", timeout=4)

    def _replace(self, domain: str, update: dict[str, object]) -> None:
        for i, r in enumerate(self._report.results):
            if r.domain == domain:
                self._report.results[i] = r.model_copy(update=update)
                break
        self.refresh_rows()


__all__ = ["ResultsScreen"]
