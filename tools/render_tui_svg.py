"""Renders the Otacon triage console to the SVG used in the README.

Companion to render_demo_svg.py. Textual draws the console, so a fenced code
block cannot show it at all; its own screenshot export is the only honest way
to put it in the README.

Runs the app headless against a real scan, or against a saved report when one
is given, so the screenshot is genuine output rather than a mock-up.

    python tools/render_tui_svg.py example.com assets/brand/demo-tui.svg
    python tools/render_tui_svg.py --from report.json assets/brand/demo-tui.svg
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from rich.console import Console

from otacon.core.models import ScanReport
from otacon.engine.scanner import run_scan
from otacon.tui.app import OtaconTUI

# Wide enough that the FLAGS column is not clipped, short enough to stay
# readable at the width a README renders an image at.
_SIZE = (150, 34)


async def _shoot(report: ScanReport, out: str) -> None:
    app = OtaconTUI(report)
    async with app.run_test(size=_SIZE) as pilot:
        # Two pauses: the first mounts the table, the second lets the dossier
        # render for the row the cursor lands on.
        await pilot.pause()
        await pilot.pause()
        Path(out).write_text(app.export_screenshot(), encoding="utf-8")


def main() -> int:
    """Scans a target (or loads a report) and writes the console screenshot."""
    args = sys.argv[1:]
    if len(args) == 3 and args[0] == "--from":
        report = ScanReport.model_validate_json(Path(args[1]).read_text(encoding="utf-8"))
        out = args[2]
    elif len(args) == 2:
        target, out = args
        report = asyncio.run(
            run_scan(
                target=target,
                concurrency=50,
                check_http=True,
                console=Console(quiet=True),
                show_progress=False,
            )
        )
    else:
        print(__doc__)
        return 2

    asyncio.run(_shoot(report, out))
    print(f"wrote {out}: {len(report.registered)} registered of {report.total_permutations}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
