"""Start-up splash for interactive mode: the wordmark decodes out of lookalikes.

Each letter of OTACON first cycles through characters an attacker would swap
in for it (0 for O, 7 for T, …) and locks into place left to right, while a
lit dot sweeps the grid like a radar. It is the tool's whole idea in half a
second, and it ends on the ordinary static BANNER.

It only plays where motion is welcome: an interactive, colour-capable
terminal. Pipes, CI, NO_COLOR and OTACON_NO_ANIMATION get the static banner.
"""

from __future__ import annotations

import os
import random
import time

from rich.console import Console
from rich.live import Live
from rich.text import Text

from .theme import BANNER, LOGO_DOTS_TOP, SPOOF_INDEX, TAGLINE, WORDMARK, gradient_color

# Plausible stand-ins per letter: digit and letter swaps a typosquatter uses.
# ASCII on purpose, so the frames stay inside the SAFE_GLYPHS font budget.
_LOOKALIKES = {"O": "0QD", "T": "7I", "A": "4@", "C": "G(", "N": "MH"}
_FRAMES = 18
_FRAME_SECONDS = 0.035


def animations_enabled(console: Console) -> bool:
    """True when the console is a real colour terminal and nobody opted out."""
    return (
        console.is_terminal
        and not console.is_dumb_terminal
        and not console.no_color
        and console.color_system is not None
        and not os.environ.get("CI")
        and not os.environ.get("OTACON_NO_ANIMATION")
    )


def _frame(step: int, rng: random.Random) -> Text:
    """One frame: sweeping dot row, half-decoded wordmark, typed-out tagline."""
    progress = step / (_FRAMES - 1)
    dots = LOGO_DOTS_TOP.split(" ")
    lit = step % len(dots)
    sweep = " ".join("●" if i == lit else "○" for i in range(len(dots)))

    locked = round(progress * len(WORDMARK))
    last = len(WORDMARK) - 1
    word = "".join(
        f"[brand.dim]{rng.choice(_LOOKALIKES.get(ch, '0'))}[/]"
        if i >= locked
        else f"[spoof]{ch}[/]"
        if i == SPOOF_INDEX
        else f"[bold {gradient_color(i / last)}]{ch}[/]"
        for i, ch in enumerate(WORDMARK)
    )

    typed = TAGLINE[: round(progress * len(TAGLINE))]
    return Text.from_markup(
        f"\n [brand]{sweep}[/]\n   {word}\n [brand.dim]{'○ ' * 5}○[/]  [muted]{typed}[/]\n"
    )


def play_intro(console: Console) -> None:
    """Plays the decode animation when allowed, then prints the static banner."""
    if animations_enabled(console):
        # Visual noise only, never security: hence the B311 waiver.
        rng = random.Random()  # nosec B311
        with Live(console=console, refresh_per_second=30, transient=True) as live:
            for step in range(_FRAMES):
                live.update(_frame(step, rng))
                time.sleep(_FRAME_SECONDS)
    console.print(BANNER)
