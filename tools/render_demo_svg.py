"""Renders a real Otacon scan to the coloured SVG used in the README.

GitHub shows fenced code blocks without colour, and the risk bars (U+2588 /
U+2591) degrade to blank boxes there — which makes the tool's best visual look
broken. Rich can export the console it already renders to, so the README shows
genuine output instead of an approximation.

    python tools/render_demo_svg.py example.com assets/brand/demo-scan.svg
"""

from __future__ import annotations

import sys

from rich.console import Console
from rich.terminal_theme import TerminalTheme

from otacon import reporters
from otacon._asyncutils import run_async
from otacon.engine.scanner import run_scan
from otacon.utils.theme import BANNER, OTACON_THEME

_ROWS = 10

# Matches the banner SVG and the terminal palette in theme.py.
OTACON_TERMINAL = TerminalTheme(
    (10, 10, 12),
    (242, 242, 242),
    [
        (58, 58, 62),
        (255, 95, 95),
        (95, 215, 0),
        (255, 215, 0),
        (95, 175, 255),
        (175, 135, 255),
        (0, 215, 175),
        (242, 242, 242),
    ],
    [
        (138, 138, 144),
        (255, 135, 135),
        (135, 255, 95),
        (255, 235, 135),
        (135, 195, 255),
        (215, 175, 255),
        (95, 235, 215),
        (255, 255, 255),
    ],
)


def main() -> int:
    """Scans *argv[1]* and writes the recorded console to *argv[2]*."""
    target, out = sys.argv[1], sys.argv[2]
    console = Console(theme=OTACON_THEME, record=True, width=100)
    report = run_async(
        run_scan(target, concurrency=50, check_http=True, console=console, show_progress=False)
    )
    # Banner, verdict and the riskiest rows: the full table of a busy target
    # is taller than any README should be.
    console.print(BANNER)
    console.print(reporters._verdict_card(report))
    console.print()
    table = reporters.build_live_table(report.registered, target, limit=_ROWS)
    if len(report.registered) > _ROWS:
        table.caption = f"+{len(report.registered) - _ROWS} more in the full report"
    console.print(table)
    console.save_svg(out, title=f"otacon scan {target}", theme=OTACON_TERMINAL)
    print(f"wrote {out}: {len(report.registered)} registered of {report.total_permutations}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
