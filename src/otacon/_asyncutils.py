"""Async utilities — event loop compatibility and concurrent execution."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Coroutine
from typing import Any

__all__ = ["run_async"]

# Windows ProactorEventLoop raises ConnectionResetError (WinError 10054) on
# normal HTTP connection teardowns. SelectorEventLoop doesn't have this issue.
# Python 3.12+ exposes loop_factory on asyncio.run().
_WIN_LOOP_FACTORY: type[asyncio.AbstractEventLoop] | None = None
if sys.platform == "win32":
    _WIN_LOOP_FACTORY = asyncio.SelectorEventLoop


def run_async[T](coro: Coroutine[Any, Any, T]) -> T:
    """Run an async coroutine with platform-appropriate event loop configuration.

    On Windows, uses SelectorEventLoop to avoid ConnectionResetError on HTTP teardowns.
    On Python 3.12+, uses loop_factory parameter.
    """
    if _WIN_LOOP_FACTORY is not None:
        return asyncio.run(coro, loop_factory=_WIN_LOOP_FACTORY)
    return asyncio.run(coro)
