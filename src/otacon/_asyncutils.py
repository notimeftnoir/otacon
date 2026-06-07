"""Async utilities — event loop compatibility and concurrent execution."""
from __future__ import annotations

import asyncio
import sys
from typing import Any, TypeVar

__all__ = ["run_async"]

T = TypeVar("T")

# Windows ProactorEventLoop raises ConnectionResetError (WinError 10054) on
# normal HTTP connection teardowns. SelectorEventLoop doesn't have this issue.
# Python 3.12+ exposes loop_factory on asyncio.run(); older versions need the
# now-deprecated set_event_loop_policy path.
_WIN_LOOP_FACTORY: type[asyncio.AbstractEventLoop] | None = None
if sys.platform == "win32":
    if sys.version_info >= (3, 12):
        _WIN_LOOP_FACTORY = asyncio.SelectorEventLoop
    else:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def run_async(coro: Any) -> Any:
    """Run an async coroutine with platform-appropriate event loop configuration.
    
    On Windows, uses SelectorEventLoop to avoid ConnectionResetError on HTTP teardowns.
    On Python 3.12+, uses loop_factory parameter; on older versions relies on
    set_event_loop_policy configuration.
    
    Args:
        coro: Coroutine to execute.
        
    Returns:
        Result of the coroutine.
    """
    if _WIN_LOOP_FACTORY is not None:
        return asyncio.run(coro, loop_factory=_WIN_LOOP_FACTORY)
    return asyncio.run(coro)
