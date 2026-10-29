"""Tests for the theme — mainly the glyph budget.

The bug these guard against is not a crash: it is the UI rendering "?" or tofu
because a codepoint is missing from the reader's terminal font. See
``otacon.utils.theme.SAFE_GLYPHS``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from otacon.utils.theme import BANNER, SAFE_GLYPHS

# UI modules: everything these print can land in a terminal. Two modules are
# deliberately excluded from this tuple:
#  - permutations.py: its non-ASCII is homoglyph *data* (Cyrillic/Greek/Armenian
#    look-alike letters), not chrome — the tool's whole job is to show these
#    literally so the analyst sees what the spoof looks like, so it must NOT be
#    held to SAFE_GLYPHS. (That data does reach a terminal, unescaped, via the
#    `generate` command — `rich.markup.escape()` there only neutralises `[`/`]`
#    markup syntax, not Unicode — so this exclusion is a deliberate scope
#    decision, not a claim that the glyphs are neutralised before they print.)
#  - reporters/html.py: it never touches a terminal — it renders raw HTML that a
#    browser paints, and browsers substitute a fallback font per-glyph instead
#    of showing tofu/'?' the way a fixed-font console does, so the console-font
#    budget SAFE_GLYPHS enforces does not apply to it.
# Paths are relative to src/otacon. These are the modules that actually write to
# a terminal; until the v2.0 cleanup this tuple named the legacy shim files
# `reporters.py` and `cli.py`, which were unreachable dead code shadowed by the
# packages of the same name — so the guard was checking files nothing rendered.
#
# A hand-kept list drifts, and this one had: the three triage-console screens
# added in 3.0.0, the verdict, the notice and `otacon watch` all print to a
# terminal and none of them were here. `test_list_covers_every_rendering_module`
# below now fails when a new one appears, so the next addition is caught rather
# than silently unguarded.
_UI_MODULES = (
    "utils/theme.py",
    "ui/glyphs.py",
    "ui/tokens.py",
    "ui/copy.py",
    "reporters/console.py",
    "cli/main.py",
    "cli/commands/scan.py",
    "cli/commands/generate.py",
    "cli/commands/diff.py",
    "engine/scanner.py",
    "tui/app.py",
    "tui/widgets.py",
    "tui/screens/start.py",
    "tui/screens/results.py",
    "tui/screens/overview.py",
    "tui/screens/settings.py",
    "tui/screens/compare.py",
    "cli/commands/tui.py",
    "cli/commands/watch.py",
    "triage/dossier.py",
    "triage/actions.py",
    "triage/verdict.py",
    "triage/notice.py",
    "reporters/markdown.py",
    "diff.py",
    "tui/commands.py",
    "ui/emit.py",
    "_splash.py",
)

_SRC = Path(__file__).resolve().parent.parent / "src" / "otacon"

# Codepoints that are text rather than chrome: accented letters cannot appear in
# a domain the reporters print, but prose in a docstring or comment may use any
# of these and they are not part of the glyph budget.
_PROSE = re.compile(r"[À-ɏ]")

# A banned glyph spelled as a \uXXXX/\UXXXXXXXX escape is invisible to a plain
# character scan — that gap is exactly how U+2691 (the old defensive flag)
# survived in reporters.py despite SAFE_GLYPHS existing: the footer emitted it
# as an escape while _domain_cell had already moved to the raw GLYPH_DEFENSIVE
# constant. Decoding escapes straight from the source text (rather than
# importing and executing the module under test) closes that gap here and for
# future glyph changes.
_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})")


def _decode_escapes(source: str) -> set[str]:
    """Characters spelled as a literal \\uXXXX/\\UXXXXXXXX escape in *source*."""
    out: set[str] = set()
    for short, long in _ESCAPE_RE.findall(source):
        c = chr(int(short or long, 16))
        if ord(c) > 127 and not _PROSE.match(c):
            out.add(c)
    return out


def _ui_glyphs(source: str) -> set[str]:
    """Every non-ASCII, non-prose character *source* can put on screen —
    written literally or spelled as a \\uXXXX escape.

    Comments and docstrings are scanned too, deliberately: a banned glyph named
    literally in a comment about banned glyphs is unreadable in exactly the
    terminal the reader is in.
    """
    direct = {c for c in source if ord(c) > 127 and not _PROSE.match(c)}
    return direct | _decode_escapes(source)


@pytest.mark.parametrize("module", _UI_MODULES)
def test_ui_modules_only_use_safe_glyphs(module: str) -> None:
    stray = _ui_glyphs((_SRC / module).read_text(encoding="utf-8")) - SAFE_GLYPHS
    assert not stray, (
        f"{module} uses {sorted(f'U+{ord(c):04X} {c}' for c in stray)}, which is not in "
        "theme.SAFE_GLYPHS. Either pick a glyph from that set or verify the new one "
        "renders in Consolas, Cascadia Mono, Courier New and JetBrains Mono first."
    )


def test_ui_glyph_scan_catches_a_banned_glyph_spelled_as_an_escape() -> None:
    """Regression guard for the blind spot that let U+2691 hide in reporters.py
    as an escape sequence instead of a raw literal — see _decode_escapes."""
    source = 'x = "\\u2691"  # old defensive flag, spelled as an escape'
    assert "⚑" in _ui_glyphs(source)
    assert "⚑" not in SAFE_GLYPHS  # sanity: it really is banned


def test_banner_encodes_on_a_legacy_windows_codepage() -> None:
    """cp1250 is what a Polish Windows console defaults to; cp850 a Western one.

    Neither can carry the banner: BANNER must contain at least one codepoint
    outside both repertoires (a strict encode raises), which is the whole
    reason cli.py's ``_ensure_unicode_output`` re-encodes those streams —
    without it, printing the banner on such a console would crash instead of
    degrading. errors="replace" is what makes that degrade to '?' instead of
    raising; a codepage that could already carry the banner losslessly would
    make this test pass vacuously; the strict-mode assertion below rules that
    out for the current banner content.
    """
    for codepage in ("cp1250", "cp850"):
        with pytest.raises(UnicodeEncodeError):
            BANNER.encode(codepage, errors="strict")
        BANNER.encode(codepage, errors="replace")


def test_the_module_list_covers_everything_that_renders() -> None:
    """A hand-kept list of rendering modules drifts; this is what notices.

    Any module importing a renderer (Rich, Textual, or our own glyph helpers)
    puts characters on a terminal and belongs in _UI_MODULES. The two documented
    exclusions stay out: the permutation rules carry homoglyph *data* that must
    print literally, and the HTML reporter targets a browser, which substitutes
    fonts per glyph instead of showing tofu.
    """
    excluded = {
        "permutations/rules.py",
        "permutations/idn.py",
        "permutations/generator.py",
        "permutations/__init__.py",
        "reporters/html.py",
    }
    renders = re.compile(
        r"^from (rich|textual)[. ]|^import (rich|textual)\b|\bglyph\(|degrade\(", re.M
    )
    unguarded = sorted(
        str(path.relative_to(_SRC))
        for path in _SRC.rglob("*.py")
        if renders.search(path.read_text(encoding="utf-8"))
        and str(path.relative_to(_SRC)) not in _UI_MODULES
        and str(path.relative_to(_SRC)) not in excluded
    )
    assert not unguarded, (
        "these modules render to a terminal but are not in _UI_MODULES:\n  "
        + "\n  ".join(unguarded)
        + "\nAdd them, or add a documented reason to `excluded` here."
    )
