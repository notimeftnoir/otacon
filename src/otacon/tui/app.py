"""Keyboard-driven triage console for an Otacon scan report.

A scan produces a few hundred rows of which a handful matter. The static table
prints all of them and then the operator scrolls. This surface instead keeps the
whole report in memory and lets one hand work it: move with the arrows, cut the
set down with a digit, read the evidence for the row under the cursor in the
pane beside it, and act on it in place.

Nothing here re-implements analysis. Rows come from a ScanReport that engine
and scoring already produced, the evidence pane renders triage.dossier._evidence,
and the abuse notice comes from triage.notice.build_takedown_notice — the same
text the questionary flow writes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import DataTable, Footer, Input, Static

from ..core.models import DomainResult, ScanReport
from ..core.types import RiskLevel
from ..net.whois import fetch_domain_age, format_age
from ..reporters.json import to_json
from ..triage.dossier import _evidence
from ..triage.notice import build_takedown_notice
from ..utils.theme import GLYPH_DEFENSIVE, WORDMARK
from ..utils.validate import safe_relative_path
from .styles import OTACON_CSS

# Semantic colours, matching OTACON_THEME. Textual markup takes hex directly.
_LEVEL_COLOR: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "#ff5f5f",
    RiskLevel.HIGH: "#ff8f5f",
    RiskLevel.MEDIUM: "#ffd700",
    RiskLevel.LOW: "#5fafff",
    RiskLevel.SAFE: "#5fd700",
}

# Digit -> level, for the 1..5 filter keys. Ordered worst-first so the key that
# is easiest to reach gives the most urgent view.
_FILTER_KEYS: dict[str, RiskLevel] = {
    "1": RiskLevel.CRITICAL,
    "2": RiskLevel.HIGH,
    "3": RiskLevel.MEDIUM,
    "4": RiskLevel.LOW,
    "5": RiskLevel.SAFE,
}

_BAR_WIDTH = 8


def _risk_bar(score: int) -> str:
    """Eight-cell density bar; the same ramp the console reporter uses."""
    filled = max(0, min(_BAR_WIDTH, round(score / 100 * _BAR_WIDTH)))
    return "█" * filled + "░" * (_BAR_WIDTH - filled)


def _badges(r: DomainResult) -> str:
    """Compact marker string for the flags that change how a row is treated."""
    marks: list[str] = []
    if r.dnsbl_listed:
        marks.append("DBL")
    if r.favicon_matches_target:
        marks.append("FAVICON")
    if r.has_login_form:
        marks.append("LOGIN")
    if r.has_mx and r.is_mail_spoofable:
        marks.append("SPOOF")
    if r.is_sinkhole:
        marks.append("SINKHOLE")
    elif r.is_parked:
        marks.append("PARKED")
    if r.is_likely_defensive:
        marks.append(GLYPH_DEFENSIVE)
    return " ".join(marks)


def _signals(r: DomainResult) -> str:
    """DNS / MX / SSL / HTTP presence, as a fixed-order checklist."""
    parts = [
        ("DNS", r.resolves),
        ("MX", r.has_mx),
        ("SSL", r.has_ssl),
    ]
    out = [name if ok else "·" * len(name) for name, ok in parts]
    out.append(str(r.http_status) if r.http_status is not None else "···")
    return " ".join(out)


def _level_counts(report: ScanReport) -> dict[RiskLevel, int]:
    """Counts registered results per risk level, for the masthead tally."""
    counts = dict.fromkeys(_LEVEL_COLOR, 0)
    for r in report.results:
        if r.is_registered:
            counts[r.risk_level] += 1
    return counts


class OtaconTUI(App[None]):
    """Interactive triage console over a completed scan report."""

    CSS = OTACON_CSS
    TITLE = "OTACON"

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("q", "quit", "quit"),
        Binding("escape", "clear_filter", "clear", show=False),
        Binding("slash", "search", "search"),
        Binding("0", "filter_all", "all"),
        Binding("1", "filter_level('1')", "crit"),
        Binding("2", "filter_level('2')", "high", show=False),
        Binding("3", "filter_level('3')", "med", show=False),
        Binding("4", "filter_level('4')", "low", show=False),
        Binding("5", "filter_level('5')", "safe", show=False),
        Binding("a", "toggle_unregistered", "unreg"),
        Binding("w", "whois", "whois"),
        Binding("t", "takedown", "takedown"),
        Binding("e", "export", "export"),
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
        table.add_column("RISK", width=_BAR_WIDTH)
        table.add_column("", width=3, key="score")
        # Widths are tuned so FLAGS — the column that changes what an operator does
        # with a row — still fits inside the rail on an 80-column terminal.
        table.add_column("DOMAIN", width=30)
        table.add_column("TECH", width=11)
        table.add_column("AGE", width=5)
        table.add_column("SIGNALS", width=15)
        table.add_column("FLAGS")
        self._refresh_rows()
        table.focus()

    # ── header text ─────────────────────────────────────────────────────

    def _brand_text(self) -> Text:
        t = Text()
        t.append(f" {WORDMARK} ", style="bold #00d7af")
        t.append("› ", style="#1c2628")  # noqa: RUF001  — UI separator, not ">"
        t.append(self._report.target, style="bold white")
        return t

    def _tally_text(self) -> Text:
        counts = _level_counts(self._report)
        t = Text()
        for level in (
            RiskLevel.CRITICAL,
            RiskLevel.HIGH,
            RiskLevel.MEDIUM,
            RiskLevel.LOW,
            RiskLevel.SAFE,
        ):
            t.append(f"{level.icon} ", style=_LEVEL_COLOR[level])
            t.append(f"{counts[level]:<4}", style="bold white")
        t.append(f"  {self._report.total_permutations} checked ", style="#8a8a8a")
        return t

    # ── row set ─────────────────────────────────────────────────────────

    def _visible(self) -> list[DomainResult]:
        rows = [r for r in self._report.results if self._show_unregistered or r.is_registered]
        if self._level is not None:
            rows = [r for r in rows if r.risk_level == self._level]
        if self._query:
            needle = self._query.lower()
            rows = [r for r in rows if needle in r.domain.lower()]
        return sorted(rows, key=lambda r: (-r.risk_score, r.domain))

    def _refresh_rows(self) -> None:
        table = self.query_one("#results", DataTable)
        table.clear()
        self._rows = self._visible()
        for r in self._rows:
            colour = _LEVEL_COLOR[r.risk_level]
            table.add_row(
                Text(_risk_bar(r.risk_score), style=colour),
                Text(str(r.risk_score), style=colour),
                Text(r.domain, style="bold white"),
                Text(r.kind.value, style="#00875f"),
                Text(format_age(r.age_days), style="#8a8a8a"),
                Text(_signals(r), style="#8a8a8a"),
                Text(_badges(r), style=colour),
            )
        self.query_one("#tally", Static).update(self._tally_text())
        self._render_dossier()

    @property
    def _selected(self) -> DomainResult | None:
        table = self.query_one("#results", DataTable)
        if not self._rows or table.cursor_row < 0 or table.cursor_row >= len(self._rows):
            return None
        return self._rows[table.cursor_row]

    # ── dossier pane ────────────────────────────────────────────────────

    def _render_dossier(self) -> None:
        body = self.query_one("#dossier-body", Static)
        r = self._selected
        if r is None:
            body.update(
                Text("no rows match the current filter", style="#5a5a5a")
                if self._rows == []
                else Text("")
            )
            return

        colour = _LEVEL_COLOR[r.risk_level]
        out = Text()
        out.append(f"{r.domain}\n", style="bold white")
        out.append(f"{r.risk_level.icon} {r.risk_level.value.upper()} ", style=colour)
        out.append(f"{r.risk_score}/100", style="bold white")
        out.append(f"   {r.kind.value}", style="#00875f")
        if r.note:
            out.append(f" · {r.note}", style="#8a8a8a")
        out.append("\n")
        out.append("─" * 40 + "\n", style="#1c2628")

        evidence = _evidence(r)
        if evidence:
            out.append("\nEVIDENCE\n", style="bold #00875f")
            for label, fact, meaning in evidence:
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
        level = _FILTER_KEYS[key]
        self._level = None if self._level == level else level
        self._refresh_rows()
        self.notify(
            "showing all levels" if self._level is None else f"level: {self._level.value}",
            timeout=2,
        )

    def action_filter_all(self) -> None:
        """Clears the level filter."""
        self._level = None
        self._refresh_rows()

    def action_toggle_unregistered(self) -> None:
        """Shows or hides variants that nobody has registered."""
        self._show_unregistered = not self._show_unregistered
        self._refresh_rows()
        self.notify(
            "including unregistered" if self._show_unregistered else "registered only", timeout=2
        )

    def action_search(self) -> None:
        """Reveals the substring filter and focuses it."""
        bar = self.query_one("#filterbar", Input)
        bar.add_class("visible")
        bar.focus()

    def action_clear_filter(self) -> None:
        """Dismisses the notice overlay, or clears the search, or drops focus back."""
        notice = self.query_one("#notice", Static)
        if notice.has_class("visible"):
            notice.remove_class("visible")
            return
        bar = self.query_one("#filterbar", Input)
        bar.value = ""
        bar.remove_class("visible")
        self._query = ""
        self._refresh_rows()
        self.query_one("#results", DataTable).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        self._query = event.value.strip()
        self._refresh_rows()

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self.query_one("#results", DataTable).focus()

    # ── actions on the selected row ─────────────────────────────────────

    def action_takedown(self) -> None:
        """Renders the abuse notice for the selected row and writes it next to the cwd."""
        r = self._selected
        if r is None:
            return
        text = build_takedown_notice(r, self._report.target)
        notice = self.query_one("#notice", Static)
        notice.update(Text(text, style="#d0d0d0"))
        notice.add_class("visible")
        self._write_beside_cwd(f"takedown-{r.domain.replace('.', '_')}.txt", text, "notice saved")

    def action_export(self) -> None:
        """Writes the selected row as a single-result JSON report."""
        r = self._selected
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
        r = self._selected
        if r is None:
            return
        if r.age_days is not None:
            self.notify(f"{r.domain}: registered {format_age(r.age_days)} ago", timeout=4)
            return
        self.notify(f"querying WHOIS for {r.domain}…", timeout=2)
        self._whois_worker(r.domain)

    def _whois_worker(self, domain: str) -> None:
        """Runs the WHOIS lookup on a worker so the event loop stays responsive."""
        self.run_worker(self._do_whois(domain), exclusive=False)

    async def _do_whois(self, domain: str) -> None:
        created, age = await fetch_domain_age(domain)
        if created is None:
            self.notify(f"{domain}: no WHOIS data", severity="warning", timeout=4)
            return
        for i, r in enumerate(self._report.results):
            if r.domain == domain:
                self._report.results[i] = r.model_copy(
                    update={"created_at": created, "age_days": age}
                )
                break
        self._refresh_rows()
        self.notify(f"{domain}: registered {format_age(age)} ago", timeout=4)


def run_tui(report: ScanReport) -> None:
    """Opens the triage console on *report*. Returns when the operator quits."""
    OtaconTUI(report).run()


__all__: list[Any] = ["OtaconTUI", "run_tui"]
