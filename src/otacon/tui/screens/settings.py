"""Settings, the allow-list and the watchlist, in one place.

Three things the tool remembers between runs, and until now none of them had
a surface: preferences lived in flags you had to retype, the allow-list could
only be added to, and the watchlist did not exist.

Everything here writes through :mod:`otacon.config`, which falls back rather
than raising, so a switched-off or unreadable store leaves a screen that
still renders and simply cannot keep anything.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Footer, OptionList, Static
from textual.widgets.option_list import Option

from ... import config
from ...core.types import RiskLevel
from ...ui.tokens import THEMES, Palette
from ...utils.theme import active_palette, glyph
from ..widgets import wordmark

# Setting key, label, and the values it cycles through. `None` means "not set",
# which is a different thing from any of the values and has to stay reachable.
_PRESETS = ("quick", "standard", "thorough")
_THRESHOLDS: tuple[str | None, ...] = (None, "low", "medium", "high", "critical")


def _next[T](values: Sequence[T], current: T) -> T:
    """The value after *current*, wrapping. An unknown value restarts the cycle.

    Unknown rather than invalid: a config file naming a theme that has since
    been renamed should move the operator back onto a real one, not refuse.
    """
    if current not in values:
        return values[0]
    return values[(values.index(current) + 1) % len(values)]


class SettingsScreen(Screen[None]):
    """What Otacon keeps between runs, and how to change it."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "app.pop_screen", "back"),
        Binding("comma", "app.pop_screen", "back", show=False),
        # No Enter binding: OptionList owns that key and would swallow a
        # screen-level one, which is the same trap the start screen documents.
        # The selection event below is what actually fires.
        Binding("d", "forget", "forget"),
        Binding("q", "app.quit", "quit"),
    ]

    def __init__(self, target: str) -> None:
        super().__init__()
        self._target = target
        self._settings = config.settings()
        self._config = config.target(target)

    @property
    def palette(self) -> Palette:
        """The palette this screen draws with."""
        app_palette = getattr(self.app, "ui_palette", None)
        return app_palette if isinstance(app_palette, Palette) else active_palette()

    def compose(self) -> ComposeResult:
        with Horizontal(id="masthead"):
            yield Static(self._brand_text(), id="brand")
            yield Static(Text("settings ", style=self.palette.muted), id="tally")
        with Vertical(id="settings"):
            yield Static("", id="settings-note")
            yield OptionList(id="settings-list")
            yield Static("", id="allow-label")
            yield OptionList(id="allow-list")
        yield Footer()

    def on_mount(self) -> None:
        self._redraw()
        self.query_one("#settings-list", OptionList).focus()

    def _brand_text(self) -> Text:
        pal = self.palette
        t = Text(" ")
        t.append_text(wordmark(palette=pal))
        t.append(glyph(" › "), style=pal.line_strong)  # noqa: RUF001  — separator, not ">"
        t.append(self._target, style=f"bold {pal.strong}")
        return t

    # ── what the rows say ───────────────────────────────────────────────

    def _rows(self) -> list[tuple[str, str, str]]:
        """Key, label and current value for each setting."""
        s = self._settings
        return [
            ("theme", "Colour theme", s.theme),
            ("ascii", "Plain characters only", "on" if s.ascii else "off"),
            ("preset", "Default scan depth", s.preset),
            ("fail_on", "Exit non-zero at", s.fail_on or "never"),
            ("watched", f"Watch {self._target}", "yes" if self._config.watched else "no"),
        ]

    def _redraw(self) -> None:
        pal = self.palette
        note = self.query_one("#settings-note", Static)
        if not config.enabled():
            note.update(
                Text(
                    "OTACON_NO_CONFIG is set, so nothing here will be kept.",
                    style=f"bold {pal.tone(RiskLevel.MEDIUM).fg}",
                )
            )
        else:
            note.update(
                Text(
                    f"Kept in {config.config_dir()}. Enter changes a row.",
                    style=pal.dim,
                )
            )

        options = self.query_one("#settings-list", OptionList)
        index = options.highlighted
        options.clear_options()
        for key, label, value in self._rows():
            line = Text(f"  {label:<26}", style=pal.body)
            line.append(value, style=f"bold {pal.brand}")
            options.add_option(Option(line, id=key))
        if index is not None and index < options.option_count:
            options.highlighted = index

        allowed = self._config.allowed
        allow_label = self.query_one("#allow-label", Static)
        allow_list = self.query_one("#allow-list", OptionList)
        allow_list.clear_options()
        if not allowed:
            allow_label.update(
                Text(
                    "\nNo domains waved through yet. Press a on a row in the "
                    "findings table to leave it out of future scans.",
                    style=pal.dim,
                )
            )
            allow_list.display = False
            return
        allow_label.update(
            Text(
                f"\nLEFT OUT OF SCANS OF {self._target.upper()}  {len(allowed)}",
                style=f"bold {pal.brand_dim}",
            )
        )
        allow_list.display = True
        for domain in allowed:
            allow_list.add_option(Option(Text(f"  {domain}", style=pal.body), id=domain))

    # ── changing them ───────────────────────────────────────────────────

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Enter on a setting advances it; Enter on an allowed domain does nothing."""
        if event.option_list.id == "settings-list":
            self._change(event.option.id)

    def action_change(self) -> None:
        """Advances the highlighted setting, for the command palette."""
        options = self.query_one("#settings-list", OptionList)
        if options.highlighted is None:
            return
        self._change(options.get_option_at_index(options.highlighted).id)

    def _change(self, key: str | None) -> None:
        """Advances one setting to its next value and stores it."""
        s = self._settings
        if key == "theme":
            s.theme = _next(tuple(THEMES), s.theme)
        elif key == "ascii":
            s.ascii = not s.ascii
        elif key == "preset":
            s.preset = _next(_PRESETS, s.preset)
        elif key == "fail_on":
            s.fail_on = _next(_THRESHOLDS, s.fail_on)
        elif key == "watched":
            self._config = config.set_watched(self._target, not self._config.watched)
            self._redraw()
            return
        else:
            return
        config.save_settings(s)
        self._redraw()
        self.notify(glyph("saved — themes and glyphs apply next run"), timeout=3)

    def action_forget(self) -> None:
        """Takes the highlighted domain back off the allow-list."""
        allow_list = self.query_one("#allow-list", OptionList)
        if not allow_list.display or allow_list.highlighted is None:
            return
        domain = allow_list.get_option_at_index(allow_list.highlighted).id
        if domain is None:
            return
        self._config = config.unallow(self._target, domain)
        self._redraw()
        self.notify(f"{domain} will be scanned again", timeout=4)


__all__ = ["SettingsScreen"]
