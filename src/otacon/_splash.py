"""Start-up splash: the wordmark decodes out of the lookalikes it warns about.

Each letter of OTACON first cycles through characters an attacker would swap
in for it (0 for O, 7 for T, …) and locks into place left to right, while a
pulse sweeps the line above. It is the tool's whole idea in half a second, and
it ends on the ordinary static banner.

Monochrome, like the mark it resolves into: the locked letters brighten, the
unlocked ones stay dim, and the homoglyph lands brightest of all. Nothing here
competes with the severity colours the scan is about to use.

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

from .ui.caps import glyph_level
from .ui.glyphs import degrade
from .ui.tokens import Palette
from .utils.theme import (
    HOMOGLYPH,
    LOGO_SWEEP,
    SPOOF_INDEX,
    TAGLINE,
    WORDMARK,
    active_palette,
    banner,
)

# Plausible stand-ins per letter: digit and letter swaps a typosquatter uses.
# ASCII on purpose, so the frames stay inside the font budget in ui.glyphs.
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


def _frame(step: int, rng: random.Random, palette: Palette) -> Text:
    """One frame: travelling pulse, half-decoded wordmark, typed-out pointer."""
    progress = step / (_FRAMES - 1)
    level = glyph_level()

    # The pulse travels rather than blinking, so the eye follows it left to
    # right in the same direction the letters lock.
    offset = step % len(LOGO_SWEEP)
    sweep = degrade(LOGO_SWEEP[offset:] + LOGO_SWEEP[:offset], level)

    locked = round(progress * len(WORDMARK))
    word = "".join(
        f"[{palette.dim}]{rng.choice(_LOOKALIKES.get(ch, '0'))}[/]"
        if i >= locked
        else f"[bold {palette.strong}]{ch}[/]"
        if i == SPOOF_INDEX
        else f"[{palette.muted}]{ch}[/]"
        for i, ch in enumerate(WORDMARK)
    )

    tail = f"{HOMOGLYPH} {degrade('·', level)} {TAGLINE}"
    typed = tail[: round(progress * len(tail))]
    pointer = f"{' ' * SPOOF_INDEX}{degrade('↑', level)} {typed}"
    return Text.from_markup(
        f"\n [{palette.dim}]{sweep}[/]\n {word}\n [{palette.dim}]{pointer}[/]\n"
    )


def play_intro(console: Console) -> None:
    """Plays the decode animation when allowed, then prints the static banner."""
    palette = active_palette()
    if animations_enabled(console):
        # Visual noise only, never security: hence the B311 waiver.
        rng = random.Random()  # nosec B311
        with Live(console=console, refresh_per_second=30, transient=True) as live:
            for step in range(_FRAMES):
                live.update(_frame(step, rng, palette))
                time.sleep(_FRAME_SECONDS)
    console.print(banner(palette))
