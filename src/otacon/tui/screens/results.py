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

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Input, Static

from ...core.models import DomainResult, ScanReport
from ...core.types import RiskLevel
from ...net.whois import fetch_domain_age, format_age
from ...reporters.json import to_json
from ...triage.actions import rescan_result
from ...triage.dossier import evidence
from ...triage.notice import build_takedown_notice
from ...utils.validate import safe_relative_path
from ..widgets import (
    BAR_WIDTH,
    FILTER_KEYS,
    LEVEL_COLOR,
    badges,
    level_counts,
    risk_bar,
    signals,
    wordmark,
)


class ResultsScreen(Screen[None]):
    """Table of findings on the right, dossier for the current row on the left."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("q", "app.quit", "quit"),
        Binding("escape", "clear_filter", "clear", show=False),
        Binding("slash", "search", "search"),
        Binding("0", "filter_all", "all"),
        Binding("1", "filter_level('1')", "crit"),
        Binding("2", "filter_level('2')", "high", show=False),
        Binding("3", "filter_level('3')", "med", show=False),
        Binding("4", "filter_level('4')", "low", show=False),
        Binding("5", "filter_level('5')", "safe", show=False),
        Binding("u", "toggle_unregistered", "unreg"),
        Binding("w", "whois", "whois"),
        Binding("o", "open_site", "open"),
        Binding("t", "takedown", "takedown"),
        Binding("e", "export", "export"),
        Binding("r", "rescan", "rescan"),
        Binding("a", "allow", "allow"),
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
        yield Static("", id="notice")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#results", DataTable)
        table.add_column("RISK", width=BAR_WIDTH)
        table.add_column("", width=3, key="score")
        # Widths are tuned so FLAGS — the column that changes what an operator
        # does with a row — still fits inside the rail on a narrow terminal.
        table.add_column("DOMAIN", width=30)
        table.add_column("TECH", width=11)
        table.add_column("AGE", width=5)
        table.add_column("SIGNALS", width=15)
        table.add_column("FLAGS")
        self.refresh_rows()
        table.focus()

    # ── header ──────────────────────────────────────────────────────────

    def _brand_text(self) -> Text:
        t = Text(" ")
        t.append_text(wordmark())
        t.append(" › ", style="#1c2628")  # noqa: RUF001  — UI separator, not ">"
        t.append(self._report.target, style="bold white")
        return t

    def _tally_text(self) -> Text:
        counts = level_counts(self._report)
        t = Text()
        for level, colour in LEVEL_COLOR.items():
            t.append(f"{level.icon} ", style=colour)
            t.append(f"{counts[level]:<4}", style="bold white")
        t.append(f"  {self._report.total_permutations} checked ", style="#8a8a8a")
        if self._report.degraded:
            pct = round(self._report.dns_failure_ratio * 100)
            t.append(f" ⚠ {pct}% DNS failed ", style="bold #ffd700")
        return t

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

    def refresh_rows(self) -> None:
        """Rebuilds the table from the report under the current filters."""
        table = self.query_one("#results", DataTable)
        table.clear()
        self._rows = self._visible()
        for r in self._rows:
            colour = LEVEL_COLOR[r.risk_level]
            table.add_row(
                Text(risk_bar(r.risk_score), style=colour),
                Text(str(r.risk_score), style=colour),
                Text(r.domain, style="bold white"),
                Text(r.kind.value, style="#00875f"),
                Text(format_age(r.age_days), style="#8a8a8a"),
                Text(signals(r), style="#8a8a8a"),
                Text(badges(r), style=colour),
            )
        self.query_one("#tally", Static).update(self._tally_text())
        self._render_dossier()

    @property
    def selected(self) -> DomainResult | None:
        """The row under the cursor, or None when the filter matches nothing."""
        table = self.query_one("#results", DataTable)
        if not self._rows or table.cursor_row < 0 or table.cursor_row >= len(self._rows):
            return None
        return self._rows[table.cursor_row]

    # ── dossier ─────────────────────────────────────────────────────────

    def _render_dossier(self) -> None:
        body = self.query_one("#dossier-body", Static)
        r = self.selected
        if r is None:
            body.update(
                Text("no rows match the current filter", style="#5a5a5a")
                if self._rows == []
                else Text("")
            )
            return

        colour = LEVEL_COLOR[r.risk_level]
        out = Text()
        out.append(f"{r.domain}\n", style="bold white")
        out.append(f"{r.risk_level.icon} {r.risk_level.value.upper()} ", style=colour)
        out.append(f"{r.risk_score}/100", style="bold white")
        out.append(f"   {r.kind.value}", style="#00875f")
        if r.note:
            out.append(f" · {r.note}", style="#8a8a8a")
        out.append("\n")
        out.append("─" * 40 + "\n", style="#1c2628")

        rows = evidence(r)
        if rows:
            out.append("\nEVIDENCE\n", style="bold #00875f")
            for label, fact, meaning in rows:
                out.append(f"  {label:<14}", style="bold #afafaf")
                out.append(f"{fact}\n", style="#ffffff")
                out.append(f"  {'':<14}{meaning}\n", style="#5a5a5a")
        else:
            out.append("\nregistered, but nothing is running\n", style="#5a5a5a")

        if r.risk_reasons:
            out.append("\nSCORING\n", style="bold #00875f")
            for reason in r.risk_reasons:
                out.append(f"  · {reason}\n", style="#8a8a8a")

        body.update(out)

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

    # ── filtering ───────────────────────────────────────────────────────

    def action_filter_level(self, key: str) -> None:
        """Restricts the table to one risk level, or lifts it if already active."""
        level = FILTER_KEYS[key]
        self._level = None if self._level == level else level
        self.refresh_rows()
        self.notify(
            "showing all levels" if self._level is None else f"level: {self._level.value}",
            timeout=2,
        )

    def action_filter_all(self) -> None:
        """Clears the level filter."""
        self._level = None
        self.refresh_rows()

    def action_toggle_unregistered(self) -> None:
        """Shows or hides variants that nobody has registered."""
        self._show_unregistered = not self._show_unregistered
        self.refresh_rows()
        self.notify(
            "including unregistered" if self._show_unregistered else "registered only", timeout=2
        )

    def action_search(self) -> None:
        """Reveals the substring filter and focuses it."""
        bar = self.query_one("#filterbar", Input)
        bar.add_class("visible")
        bar.focus()

    def action_clear_filter(self) -> None:
        """Dismisses the overlay, or clears the search, or drops focus back."""
        notice = self.query_one("#notice", Static)
        if notice.has_class("visible"):
            notice.remove_class("visible")
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
        warning.append("⚠  OPSEC warning\n\n", style="bold #ffd700")
        warning.append(f"{r.domain} is rated {r.risk_level.value}. ", style="#d0d0d0")
        warning.append(
            "Opening it in your own browser exposes your address and fingerprint "
            "to whoever runs it.\n\n",
            style="#d0d0d0",
        )
        warning.append("Defanged IOC   ", style="bold #afafaf")
        warning.append(f"hxxps://{defanged}\n", style="#ffffff")
        warning.append("Sandbox        ", style="bold #afafaf")
        warning.append(f"https://urlscan.io/search/#{quote(r.domain)}\n\n", style="#5fafff")
        warning.append("Press o again to open anyway, Esc to cancel.", style="bold #ff8f5f")
        notice.update(warning)
        notice.add_class("visible")

    def action_takedown(self) -> None:
        """Renders the abuse notice for the selected row and writes it to the cwd."""
        r = self.selected
        if r is None:
            return
        text = build_takedown_notice(r, self._report.target)
        notice = self.query_one("#notice", Static)
        notice.update(Text(text, style="#d0d0d0"))
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
