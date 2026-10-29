"""Renders a real Otacon scan to the coloured SVG used in the README.

GitHub shows fenced code blocks without colour, and the density glyphs
(U+2588 / U+2591) degrade to blank boxes there — which makes the tool's best
visual look broken. Rich can export the console it already renders to, so the
README shows genuine output instead of an approximation.

    python tools/render_demo_svg.py example.com assets/brand/demo-scan.svg
    python tools/render_demo_svg.py --from report.json assets/brand/demo-scan.svg

The `--from` form exists so the README's two screenshots can be rendered from
one scan and therefore agree on their numbers.
"""

from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console

from otacon._asyncutils import run_async
from otacon.core.models import ScanReport
from otacon.engine.scanner import run_scan
from otacon.reporters import console as reporters
from otacon.ui.emit import terminal_theme
from otacon.utils.theme import BANNER, OTACON_THEME, active_palette

_ROWS = 10


def _load(args: list[str]) -> tuple[ScanReport, str] | None:
    """Resolves argv into a report and an output path, or None on bad usage."""
    if len(args) == 3 and args[0] == "--from":
        raw = Path(args[1]).read_text(encoding="utf-8")
        return ScanReport.model_validate_json(raw), args[2]
    if len(args) == 2:
        report = run_async(
            run_scan(
                args[0],
                concurrency=50,
                check_http=True,
                console=Console(quiet=True),
                show_progress=False,
            )
        )
        return report, args[1]
    return None


def main() -> int:
    """Scans a target (or loads a report) and writes the recorded console."""
    loaded = _load(sys.argv[1:])
    if loaded is None:
        print(__doc__)
        return 2
    report, out = loaded

    console = Console(theme=OTACON_THEME, record=True, width=100)
    console.print(BANNER)
    # The same renderer `otacon scan` prints through, so the screenshot cannot
    # drift from the output it claims to show.
    reporters.render_table(report, console, top=_ROWS)
    console.save_svg(
        out,
        title=f"otacon scan {report.target}",
        theme=terminal_theme(active_palette()),
    )
    print(f"wrote {out}: {len(report.registered)} registered of {report.total_permutations}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
