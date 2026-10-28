"""The glyph budget, and an ASCII fallback for every symbol in it.

``SAFE`` is the set of non-ASCII codepoints the terminal surfaces are allowed
to print. It is small on purpose: every member was checked to render in
Consolas, Cascadia Mono, Courier New and JetBrains Mono, because the failure
mode is not a crash — it is the interface quietly showing '?' or tofu to a
reader who then assumes the tool is broken.

``tests/test_theme.py`` scans the UI modules against ``SAFE`` and fails on any
stray codepoint, including one spelled as a ``\\uXXXX`` escape. Adding a glyph
means checking those four fonts first.

``ASCII_FALLBACK`` is what makes ``--ascii`` possible: before this existed the
budget was documented but nothing degraded to it, so a terminal that could not
meet it simply rendered badly.
"""

from __future__ import annotations

from .caps import GlyphLevel

SAFE = frozenset(
    "○●"
    "░▒▓█"
    "»"
    "✓✗"
    "⚠"
    "→←↑↓"
    "►•"
    "О"  # noqa: RUF001  — U+041E, the homoglyph the wordmark is built on
    "·—…›─"  # noqa: RUF001
)

# Deliberately lossy. A density ramp degrades to a weight ramp, which keeps
# the ordering readable even though it stops being pretty.
ASCII_FALLBACK = {
    "○": "o",
    "●": "O",
    "░": ".",
    "▒": ":",
    "▓": "+",
    "█": "#",
    "»": ">>",
    "✓": "y",
    "✗": "n",
    "⚠": "!",
    "→": "->",
    "←": "<-",
    "↑": "^",
    "↓": "v",
    "►": ">",
    "•": "*",
    "О": "O",  # noqa: RUF001
    "·": ".",
    "—": "--",
    "…": "...",
    "›": ">",  # noqa: RUF001  — UI separator, not ">"
    "─": "-",
}


def degrade(text: str, level: GlyphLevel) -> str:
    """Rewrites *text* so it survives *level*.

    At ``FULL`` this is the identity. At ``ASCII`` every budgeted glyph is
    swapped for its stand-in and anything else above U+007F is dropped rather
    than guessed at, since a wrong guess is worse than a gap.
    """
    if level is GlyphLevel.FULL:
        return text
    out: list[str] = []
    for ch in text:
        if ord(ch) < 128:
            out.append(ch)
        else:
            out.append(ASCII_FALLBACK.get(ch, ""))
    return "".join(out)


__all__ = ["ASCII_FALLBACK", "SAFE", "degrade"]
