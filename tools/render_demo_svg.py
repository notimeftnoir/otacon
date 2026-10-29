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

from otacon._asyncutils import run_async
from otacon.engine.scanner import run_scan
from otacon.reporters import console as reporters
from otacon.ui.emit import terminal_theme
from otacon.utils.theme import BANNER, OTACON_THEME, active_palette

_ROWS = 10


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
    # The live palette, not a copy of it: this file used to carry its own
    # TerminalTheme under a comment promising it matched, and by 3.0.0 it had
    # drifted in eleven of eighteen slots — the README screenshots were painted
    # in colours the tool no longer used.
    console.save_svg(out, title=f"otacon scan {target}", theme=terminal_theme(active_palette()))
    print(f"wrote {out}: {len(report.registered)} registered of {report.total_permutations}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
