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
from textual.widgets import (
    Checkbox,
    Collapsible,
    Footer,
    Input,
    OptionList,
    ProgressBar,
    RadioButton,
    RadioSet,
    Static,
)
from textual.widgets.option_list import Option

from ... import history
from ...core.models import ScanReport
from ...core.types import RiskLevel
from ...engine.scanner import run_scan
from ...triage.verdict import Delta, delta
from ...ui.tokens import Palette
from ...utils.theme import active_palette
from ...utils.validate import is_valid_domain, normalize_domain
from ..widgets import logo
from .overview import OverviewScreen

# Label, option name, default. WHOIS dominates the wall clock on a busy target,
# so it is the one an impatient operator turns off first — but it is on by
# default because domain age is the strongest single signal of a live campaign.
_OPTIONS: tuple[tuple[str, str, bool], ...] = (
    ("Websites and certificates (HTTP/TLS)", "check_http", True),
    ("Registration dates (WHOIS/RDAP)", "check_whois", True),
    ("Reputation lists (Spamhaus/SURBL)", "check_dnsbl", True),
    ("Certificate Transparency discovery", "check_ct", True),
)

# Presets, fastest first. Four checkboxes named after protocols are a fair ask
# of an operator and an unfair one of everybody else, so the choice is offered
# as speed — which is what the reader actually cares about — and the switches
# stay underneath for whoever wants them.
#
# Thorough is the default because it is what the tool did before presets
# existed: a preset must not quietly make a scan miss something.
_PRESETS: tuple[tuple[str, str, dict[str, bool]], ...] = (
    (
        "Quick",
        "names only, about ten seconds",
        {"check_http": False, "check_whois": False, "check_dnsbl": False, "check_ct": False},
    ),
    (
        "Standard",
        "also checks websites and reputation",
        {"check_http": True, "check_whois": False, "check_dnsbl": True, "check_ct": False},
    ),
    (
        "Thorough",
        "everything, plus registration dates",
        {"check_http": True, "check_whois": True, "check_dnsbl": True, "check_ct": True},
    ),
)
_DEFAULT_PRESET = 2


class StartScreen(Screen[None]):
    """Takes a target and the scan options, then runs the scan."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("q", "app.quit", "quit"),
        # No screen-level Enter binding: it would outrank the focused widget and
        # swallow the key before the recent-scans list could open a stored run.
        # The target field starts the scan through its own submit event.
    ]

    def __init__(self) -> None:
        super().__init__()
        # Not _running: textual.message_pump.MessagePump already owns that name
        # on every Screen and sets it True once the screen starts, which silently
        # made this screen believe a scan was always in progress.
        self._scanning = False
        self._started = 0.0

    @property
    def palette(self) -> Palette:
        """The palette this screen draws with."""
        app_palette = getattr(self.app, "ui_palette", None)
        return app_palette if isinstance(app_palette, Palette) else active_palette()

    @property
    def _bad(self) -> str:
        """Style for a message that stopped the operator getting a scan."""
        return self.palette.tone(RiskLevel.CRITICAL).fg

    @property
    def _busy(self) -> str:
        """Style for progress the operator is waiting on."""
        return self.palette.brand

    def compose(self) -> ComposeResult:
        with Middle(), Center(), Vertical(id="setup"):
            yield Static(self._brand_text(), id="setup-brand")
            yield Static(
                "Type the domain you want to protect. Otacon builds the lookalikes "
                "an attacker could register and checks which ones exist.",
                id="setup-help",
            )
            yield Input(placeholder="example.com", id="target")
            yield Static("HOW DEEP", id="preset-label")
            with RadioSet(id="preset"):
                for i, (name, blurb, _flags) in enumerate(_PRESETS):
                    yield RadioButton(
                        f"{name}  —  {blurb}", value=i == _DEFAULT_PRESET, id=f"preset-{i}"
                    )
            # Textual's default chevrons are outside the font budget in
            # ui.glyphs; these two are in it and read the same way.
            with Collapsible(
                title="Advanced",
                collapsed=True,
                id="advanced",
                collapsed_symbol="→",
                expanded_symbol="↓",
            ):
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

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Applies the chosen preset to the switches underneath.

        The switches stay the single source of truth for what runs, so opening
        Advanced always shows what the preset actually selected rather than a
        second, possibly disagreeing, record of the choice.
        """
        if self._scanning:
            return
        _name, _blurb, flags = _PRESETS[event.index]
        for _label, name, _default in _OPTIONS:
            self.query_one(f"#opt-{name}", Checkbox).value = flags[name]

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Reopens a stored scan. No network traffic at all."""
        if self._scanning or event.option.id is None:
            return
        try:
            report = history.load(Path(event.option.id))
        except Exception as exc:
            self.query_one("#setup-status", Static).update(
                Text(f"Could not read that scan: {exc}", style=self._bad)
            )
            return
        # No delta: a reopened scan is being read, not compared, and the run
        # before it is not necessarily the one the reader has in mind.
        self.app.push_screen(OverviewScreen(report))

    def _brand_text(self) -> Text:
        return logo()

    # ── starting the scan ───────────────────────────────────────────────

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self.action_start()

    def action_start(self) -> None:
        """Validates the target and launches the scan, once."""
        if self._scanning:
            return
        raw = self.query_one("#target", Input).value.strip()
        target = normalize_domain(raw)
        status = self.query_one("#setup-status", Static)
        if not raw:
            status.update(
                Text("Type a domain first.", style=self.palette.tone(RiskLevel.MEDIUM).fg)
            )
            return
        if not is_valid_domain(target):
            status.update(Text(f"{raw!r} is not a valid domain.", style=self._bad))
            return

        options = {
            name: self.query_one(f"#opt-{name}", Checkbox).value for _label, name, _d in _OPTIONS
        }
        self._scanning = True
        self._started = time.monotonic()
        self.query_one("#target", Input).disabled = True
        self.query_one("#preset", RadioSet).disabled = True
        for _label, name, _d in _OPTIONS:
            self.query_one(f"#opt-{name}", Checkbox).disabled = True
        self.query_one("#setup-progress", ProgressBar).display = True
        status.update(Text(f"Scanning {target}…", style=self._busy))
        self.run_worker(self._scan(target, options), exclusive=True)

    def _on_progress(self, done: int, total: int) -> None:
        """Called from the scan; marshalled onto the UI thread by call_from_thread."""
        bar = self.query_one("#setup-progress", ProgressBar)
        bar.update(total=total, progress=done)
        elapsed = time.monotonic() - self._started
        self.query_one("#setup-status", Static).update(
            Text(f"Checked {done} of {total}  ·  {elapsed:.0f}s", style=self._busy)
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
        # Read the previous run before storing this one, or the comparison is
        # against the scan that just finished.
        change = self._since_last(target, report)
        try:
            history.save(report)
        except Exception as exc:
            # Losing the history entry must never lose the scan the operator
            # just waited for.
            self.notify(f"could not store this scan: {exc}", severity="warning", timeout=5)
        self.app.push_screen(OverviewScreen(report, change))

    def _since_last(self, target: str, report: ScanReport) -> Delta | None:
        """What moved since the previous stored scan of *target*, if there is one."""
        try:
            previous = history.latest(target)
        except Exception:
            # History is a convenience. A corrupt or unreadable store must not
            # cost the operator the scan they just waited for.
            return None
        return delta(previous, report) if previous is not None else None

    def _fail(self, message: str) -> None:
        """Returns the form to an editable state so the operator can retry."""
        self._scanning = False
        self.query_one("#setup-progress", ProgressBar).display = False
        self.query_one("#target", Input).disabled = False
        self.query_one("#preset", RadioSet).disabled = False
        for _label, name, _d in _OPTIONS:
            self.query_one(f"#opt-{name}", Checkbox).disabled = False
        self.query_one("#setup-status", Static).update(Text(message, style=self._bad))


__all__ = ["StartScreen"]
