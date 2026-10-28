"""Turns a ``Palette`` into whatever each renderer expects.

This is the only module that knows both the palette and a rendering library,
which is what keeps ``tokens.py`` pure and keeps the four surfaces from
drifting: they no longer hold colours, they ask for them.

The semantic style names below (``brand``, ``warn``, ``danger`` …) are the
ones the console reporter has always used, so adopting this layer changed no
call sites — only where the colours come from.
"""

from __future__ import annotations

from rich.color import Color
from rich.terminal_theme import TerminalTheme
from rich.theme import Theme

from ..core.types import RiskLevel
from .caps import ColorDepth, gradient_stops
from .tokens import Palette


def rich_theme(palette: Palette) -> Theme:
    """The Rich theme for *palette*.

    ``critical`` is plain weight-and-hue here. It used to be the one token
    with a background (``bold white on #870000``), which meant an age cell or
    a badge rendered as a red block inside the table and read as a rendering
    fault rather than as emphasis. The verdict card gets its emphasis from the
    panel border instead.
    """
    crit = palette.tone(RiskLevel.CRITICAL)
    return Theme(
        {
            "brand": f"bold {palette.brand}",
            "brand.dim": palette.brand_dim,
            "info": palette.accent,
            "muted": f"dim {palette.muted}",
            "dim": palette.dim,
            "ok": f"bold {palette.tone(RiskLevel.SAFE).fg}",
            "warn": f"bold {palette.tone(RiskLevel.MEDIUM).fg}",
            "danger": f"bold {palette.tone(RiskLevel.HIGH).fg}",
            "critical": f"bold {crit.fg}",
            "crit.bar": crit.fg,
            "field": palette.body if palette.dark else palette.muted,
            "value": palette.strong,
            "url": f"underline {palette.accent}",
            "spoof": f"bold {crit.fg}",
            "rule": palette.line,
        }
    )


def textual_vars(palette: Palette) -> dict[str, str]:
    """Design tokens for ``App.get_css_variables()``.

    Textual CSS cannot read Python constants, which is why ``tui/styles.py``
    used to repeat every colour as a hex literal and needed an anti-drift
    test. Feeding the stylesheet ``$otacon-*`` variables removes the copy, so
    there is nothing left to drift.
    """
    out = {
        "otacon-bg": palette.bg,
        "otacon-surface": palette.surface,
        "otacon-raised": palette.raised,
        "otacon-line": palette.line,
        "otacon-line-strong": palette.line_strong,
        "otacon-dim": palette.dim,
        "otacon-muted": palette.muted,
        "otacon-body": palette.body,
        "otacon-strong": palette.strong,
        "otacon-brand": palette.brand,
        "otacon-brand-dim": palette.brand_dim,
        "otacon-accent": palette.accent,
        "otacon-select": palette.select,
    }
    for level in RiskLevel:
        tone = palette.tone(level)
        out[f"otacon-risk-{level.value}"] = tone.fg
        out[f"otacon-wash-{level.value}"] = tone.wash
    return out


def mix(a: str, b: str, t: float) -> str:
    """Blends *a* toward *b* by *t* (0..1), as hex.

    Used where a surface needs a shade the palette does not name outright —
    a badge background, say — so the shade still tracks the theme instead of
    becoming another hard-coded literal.
    """
    ca, cb = Color.parse(a).get_truecolor(), Color.parse(b).get_truecolor()
    r, g, bl = (round(x + (y - x) * t) for x, y in zip(ca, cb, strict=True))
    return f"#{r:02x}{g:02x}{bl:02x}"


def html_vars(palette: Palette) -> str:
    """The ``:root`` custom-property block for the HTML report.

    ``--border`` stays the dimmed brand rather than the neutral hairline: the
    report's green rules are a deliberate terminal reference, and the neutral
    is offered alongside as ``--line`` for the surfaces that want it.
    """
    crit = palette.tone(RiskLevel.CRITICAL)
    if palette.dark:
        # White on a darkened red. Mixing toward the background keeps the badge
        # legible on every dark theme, including the hueless one.
        crit_fg, crit_bg = palette.strong, mix(crit.fg, palette.bg, 0.55)
    else:
        # Inverted on light: a dark-red badge on paper is a smudge.
        crit_fg, crit_bg = crit.fg, crit.wash
    lines = [
        f"--bg:{palette.bg}",
        f"--surface:{palette.surface}",
        f"--surface2:{palette.raised}",
        f"--border:{palette.brand_dim}",
        f"--line:{palette.line}",
        f"--line-strong:{palette.line_strong}",
        f"--brand:{palette.brand}",
        f"--brand-dim:{palette.brand_dim}",
        f"--accent:{palette.accent}",
        f"--dim:{palette.dim}",
        f"--muted:{palette.muted}",
        f"--field:{palette.body if palette.dark else palette.muted}",
        f"--value:{palette.strong}",
        f"--ok:{palette.tone(RiskLevel.SAFE).fg}",
        f"--info:{palette.tone(RiskLevel.LOW).fg}",
        f"--warn:{palette.tone(RiskLevel.MEDIUM).fg}",
        f"--danger:{palette.tone(RiskLevel.HIGH).fg}",
        f"--critical:{crit.fg}",
        f"--crit-fg:{crit_fg}",
        f"--crit-bg:{crit_bg}",
    ]
    for level in RiskLevel:
        lines.append(f"--wash-{level.value}:{palette.tone(level).wash}")
    return ";".join(lines) + ";"


def _rgb(hex_colour: str) -> tuple[int, int, int]:
    triplet = Color.parse(hex_colour).get_truecolor()
    return (triplet.red, triplet.green, triplet.blue)


def terminal_theme(palette: Palette) -> TerminalTheme:
    """The SVG export theme, so README screenshots match the live terminal."""
    risk = palette.risk
    return TerminalTheme(
        _rgb(palette.bg),
        _rgb(palette.body),
        [
            _rgb(palette.line_strong),
            _rgb(risk[RiskLevel.CRITICAL].fg),
            _rgb(risk[RiskLevel.SAFE].fg),
            _rgb(risk[RiskLevel.MEDIUM].fg),
            _rgb(risk[RiskLevel.LOW].fg),
            _rgb(risk[RiskLevel.HIGH].fg),
            _rgb(palette.brand),
            _rgb(palette.body),
        ],
        [
            _rgb(palette.muted),
            _rgb(risk[RiskLevel.HIGH].fg),
            _rgb(risk[RiskLevel.SAFE].fg),
            _rgb(risk[RiskLevel.MEDIUM].fg),
            _rgb(palette.accent),
            _rgb(risk[RiskLevel.CRITICAL].fg),
            _rgb(palette.brand),
            _rgb(palette.strong),
        ],
    )


def gradient_color(t: float, stops: tuple[str, ...]) -> str:
    """Hex colour at position *t* (0..1) along *stops*, linearly interpolated."""
    if len(stops) == 1:
        return stops[0]
    t = min(max(t, 0.0), 1.0) * (len(stops) - 1)
    i = min(int(t), len(stops) - 2)
    a = Color.parse(stops[i]).get_truecolor()
    b = Color.parse(stops[i + 1]).get_truecolor()
    f = t - i
    r, g, bl = (round(x + (y - x) * f) for x, y in zip(a, b, strict=True))
    return f"#{r:02x}{g:02x}{bl:02x}"


def gradient_for(palette: Palette, depth: ColorDepth) -> tuple[str, ...]:
    """The wordmark ramp for *palette*, degraded to what *depth* can show."""
    return gradient_stops(palette, depth)


__all__ = [
    "gradient_color",
    "gradient_for",
    "html_vars",
    "mix",
    "rich_theme",
    "terminal_theme",
    "textual_vars",
]
