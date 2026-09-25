"""Tests for the theme — mainly the glyph budget.

The bug these guard against is not a crash: it is the UI rendering "?" or tofu
because a codepoint is missing from the reader's terminal font. See
``otacon.theme.SAFE_GLYPHS``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from otacon.theme import BANNER, GLYPH_DEFENSIVE, SAFE_GLYPHS, RiskLevel

# UI modules: everything these print can land in a terminal. Two modules are
# deliberately excluded from this tuple:
#  - permutations.py: its non-ASCII is homoglyph *data* (Cyrillic/Greek/Armenian
#    look-alike letters), not chrome — the tool's whole job is to show these
#    literally so the analyst sees what the spoof looks like, so it must NOT be
#    held to SAFE_GLYPHS. (That data does reach a terminal, unescaped, via
#    cli.py's `generate` command and interactive.py's `_interactive_generate` —
#    `rich.markup.escape()` there only neutralises `[`/`]` markup syntax, not
#    Unicode — so this exclusion is a deliberate scope decision, not a claim
#    that the glyphs are somehow neutralised before they print.)
#  - html_report.py: it never touches a terminal — it renders raw HTML that a
#    browser paints, and browsers substitute a fallback font per-glyph instead
#    of showing tofu/'?' the way a fixed-font console does, so the console-font
#    budget SAFE_GLYPHS enforces does not apply to it.
_UI_MODULES = ("theme.py", "reporters.py", "interactive.py", "cli.py", "_scanner.py")

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


def test_risk_icons_are_distinct_and_safe() -> None:
    icons = [level.icon for level in RiskLevel]
    assert len(set(icons)) == len(icons)
    assert set(icons) <= SAFE_GLYPHS


def test_defensive_marker_is_safe() -> None:
    assert set(GLYPH_DEFENSIVE) <= SAFE_GLYPHS


def test_banner_is_safe() -> None:
    assert _ui_glyphs(BANNER) <= SAFE_GLYPHS


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
