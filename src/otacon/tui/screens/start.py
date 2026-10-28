"""The opening screen: name a target, choose how deep to look, watch it run.

`otacon` with no arguments lands here, so this screen owns the whole flow the
guided prompts used to: it takes the domain, carries the scan options, runs the
scan on a worker, and hands the finished report to the results screen.

Scanning here rather than before the application starts keeps the terminal in
one mode for the whole session, and lets the progress bar report the same
counts the console reporter draws for itself.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import ClassVar

from rich.console import Console
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Middle, Vertical
from textual.screen import Screen
from textual.widgets import Checkbox, Footer, Input, OptionList, ProgressBar, Static
from textual.widgets.option_list import Option

from ... import history
from ...engine.scanner import run_scan
from ...utils.validate import is_valid_domain, normalize_domain
from ..widgets import logo
from .results import ResultsScreen

# Label, option name, default. WHOIS dominates the wall clock on a busy target,
# so it is the one an impatient operator turns off first — but it is on by
# default because domain age is the strongest single signal of a live campaign.
_OPTIONS: tuple[tuple[str, str, bool], ...] = (
    ("Websites and certificates (HTTP/TLS)", "check_http", True),
    ("Registration dates (WHOIS/RDAP)", "check_whois", True),
    ("Reputation lists (Spamhaus/SURBL)", "check_dnsbl", True),
    ("Certificate Transparency discovery", "check_ct", True),
)


class StartScreen(Screen[None]):
    """Takes a target and the scan options, then runs the scan."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("q", "app.quit", "quit"),
        Binding("enter", "start", "scan", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._running = False
        self._started = 0.0

    def compose(self) -> ComposeResult:
        with Middle(), Center(), Vertical(id="setup"):
            yield Static(self._brand_text(), id="setup-brand")
            yield Static(
                "Type the domain you want to protect. Otacon builds the lookalikes "
                "an attacker could register and checks which ones exist.",
                id="setup-help",
            )
            yield Input(placeholder="example.com", id="target")
            for label, name, default in _OPTIONS:
                yield Checkbox(label, value=default, id=f"opt-{name}")
            yield Static("", id="setup-status")
            yield ProgressBar(total=100, show_eta=False, id="setup-progress")
            yield Static("RECENT SCANS", id="recent-label")
            yield OptionList(id="recent")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#setup-progress", ProgressBar).display = False
        self._load_recent()
        self.query_one("#target", Input).focus()

    def _load_recent(self) -> None:
        """Lists stored scans so a target can be reopened without the network."""
        recent = self.query_one("#recent", OptionList)
        label = self.query_one("#recent-label", Static)
        recent.clear_options()
        entries: list[tuple[str, history.ScanRecord]] = []
        for target in history.targets():
            entries.extend((target, record) for record in history.scans(target, limit=5))
        entries.sort(key=lambda pair: pair[1].started_at, reverse=True)
        if not entries:
            label.display = False
            recent.display = False
            return
        label.display = True
        recent.display = True
        for target, record in entries[:8]:
            recent.add_option(Option(f"{target:<28} {record.label}", id=str(record.path)))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Reopens a stored scan. No network traffic at all."""
        if self._running or event.option.id is None:
            return
        try:
            report = history.load(Path(event.option.id))
        except Exception as exc:
            self.query_one("#setup-status", Static).update(
                Text(f"Could not read that scan: {exc}", style="#ff5f5f")
            )
            return
        self.app.push_screen(ResultsScreen(report))

    def _brand_text(self) -> Text:
        return logo()

    # ── starting the scan ───────────────────────────────────────────────

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self.action_start()

    def action_start(self) -> None:
        """Validates the target and launches the scan, once."""
        if self._running:
            return
        raw = self.query_one("#target", Input).value.strip()
        target = normalize_domain(raw)
        status = self.query_one("#setup-status", Static)
        if not raw:
            status.update(Text("Type a domain first.", style="#ffd700"))
            return
        if not is_valid_domain(target):
            status.update(Text(f"{raw!r} is not a valid domain.", style="#ff5f5f"))
            return

        options = {
            name: self.query_one(f"#opt-{name}", Checkbox).value for _label, name, _d in _OPTIONS
        }
        self._running = True
        self._started = time.monotonic()
        self.query_one("#target", Input).disabled = True
        for _label, name, _d in _OPTIONS:
            self.query_one(f"#opt-{name}", Checkbox).disabled = True
        self.query_one("#setup-progress", ProgressBar).display = True
        status.update(Text(f"Scanning {target}…", style="#00d7af"))
        self.run_worker(self._scan(target, options), exclusive=True)

    def _on_progress(self, done: int, total: int) -> None:
        """Called from the scan; marshalled onto the UI thread by call_from_thread."""
        bar = self.query_one("#setup-progress", ProgressBar)
        bar.update(total=total, progress=done)
        elapsed = time.monotonic() - self._started
        self.query_one("#setup-status", Static).update(
            Text(f"Checked {done} of {total}  ·  {elapsed:.0f}s", style="#00d7af")
        )

    async def _scan(self, target: str, options: dict[str, bool]) -> None:
        try:
            report = await run_scan(
                target=target,
                concurrency=50,
                console=Console(quiet=True),
                show_progress=False,
                on_progress=self._on_progress,
                check_http=options["check_http"],
                check_whois=options["check_whois"],
                check_dnsbl=options["check_dnsbl"],
                check_ct=options["check_ct"],
            )
        except Exception as exc:
            self._fail(f"Scan failed: {exc}")
            return
        if not report.results:
            self._fail(f"No variants could be generated for {target}.")
            return
        try:
            history.save(report)
        except Exception as exc:
            # Losing the history entry must never lose the scan the operator
            # just waited for.
            self.notify(f"could not store this scan: {exc}", severity="warning", timeout=5)
        self.app.push_screen(ResultsScreen(report))

    def _fail(self, message: str) -> None:
        """Returns the form to an editable state so the operator can retry."""
        self._running = False
        self.query_one("#setup-progress", ProgressBar).display = False
        self.query_one("#target", Input).disabled = False
        for _label, name, _d in _OPTIONS:
            self.query_one(f"#opt-{name}", Checkbox).disabled = False
        self.query_one("#setup-status", Static).update(Text(message, style="#ff5f5f"))


__all__ = ["StartScreen"]
