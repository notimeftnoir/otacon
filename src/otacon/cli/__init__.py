"""Typer CLI entry point for Otacon.

Only ``app`` leaves this module. It used to re-export forty names so that a
test could reach any CLI helper through one import — including ``sys``,
``Path``, ``Enum`` and ``dataclass``, which made four stdlib objects part of
Otacon's apparent public API. Nothing imported them: every caller reaches
helpers by their real module path, which is also the only path that
monkeypatching works through.
"""

from __future__ import annotations

from .main import app

__all__ = ["app"]
