"""CLI runtime state management."""

from __future__ import annotations

from dataclasses import dataclass

import typer


@dataclass(frozen=True)
class _CliState:
    """Per-invocation state stored on typer.Context.obj."""

    quiet: bool = False


def _state(ctx: typer.Context) -> _CliState:
    """Extracts or defaults the active _CliState."""
    obj = ctx.obj
    return obj if isinstance(obj, _CliState) else _CliState()


__all__ = ["_CliState", "_state"]
