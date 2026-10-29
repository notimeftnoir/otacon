"""The command palette, taught the tool's own commands.

Textual gives every application a palette on ctrl+p. Out of the box it lists
the framework's commands — change theme, take a screenshot, quit — and nothing
about the thing the operator is actually doing, which makes it a feature that
exists without being useful.

Everything the results screen can do is reachable by a single key, and the
help overlay lists them. This is for the other direction: knowing what you
want to do and not remembering which letter it was.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from textual.command import DiscoveryHit, Hit, Hits, Provider

# Command, what it does, and the action to run. The wording matches the help
# overlay, because two names for one action is how an interface stops being
# learnable.
_COMMANDS: tuple[tuple[str, str, str], ...] = (
    ("Sort rows", "risk, name, age or technique", "sort"),
    ("Mark row", "mark the current row and move on", "toggle_select"),
    ("Mark everything shown", "or clear the marks", "select_visible"),
    ("Export this view", "every row the filter shows", "export_view"),
    ("Export marked rows", "as a JSON report", "export"),
    ("Write abuse notices", "for the marked rows", "takedown"),
    ("Hide marked rows", "for this session only", "allow"),
    ("Re-check this row", "probe it again now", "rescan"),
    ("Look up registration date", "WHOIS or RDAP", "whois"),
    ("Open the site", "warns before it does", "open_site"),
    ("Search domains", "filter by part of a name", "search"),
    ("Show every severity", "clear the level filter", "filter_all"),
    ("Dim the quiet rows", "focus on the worst band present", "toggle_focus"),
    ("Show risk bars", "instead of the severity glyph", "toggle_bars"),
    ("Include unregistered", "show variants nobody registered", "toggle_unregistered"),
    ("Help and glossary", "keys, score bands, every flag", "help"),
)


class OtaconCommands(Provider):
    """Puts the triage console's own actions in the command palette."""

    def _runnable(self) -> Iterable[tuple[str, str, str]]:
        """The commands the screen on top can actually run."""
        screen = self.screen
        for title, blurb, action in _COMMANDS:
            if hasattr(screen, f"action_{action}"):
                yield title, blurb, action

    async def discover(self) -> Hits:
        """What the palette offers before anything has been typed."""
        for title, blurb, action in self._runnable():
            yield DiscoveryHit(title, self._run(action), help=blurb)

    async def search(self, query: str) -> Hits:
        """Commands matching *query*."""
        matcher = self.matcher(query)
        for title, blurb, action in self._runnable():
            score = matcher.match(title)
            if score > 0:
                yield Hit(score, matcher.highlight(title), self._run(action), help=blurb)

    def _run(self, action: str) -> Callable[[], None]:
        """A callable that runs *action* on whichever screen is on top.

        The screen is looked up when the hit is chosen, not when it is listed:
        the palette closes before the command runs, and by then the screen on
        top may be a different one.
        """

        def runner() -> None:
            self.app.call_next(getattr(self.screen, f"action_{action}"))

        return runner


__all__ = ["OtaconCommands"]
