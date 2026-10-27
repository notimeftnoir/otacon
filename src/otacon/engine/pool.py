"""Operating system resource and file descriptor limit management."""

from __future__ import annotations

import logging
import resource

_log = logging.getLogger("otacon.engine.pool")


class ResourceLimiter:
    """Manages adaptive concurrency bounded by OS file descriptor limits."""

    @staticmethod
    def compute_safe_concurrency(requested: int) -> int:
        """Calculates bounded concurrency preventing EMFILE (Too many open files)."""
        try:
            soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            # Reserve 64 FDs for stdio, logs, and internal tasks; divide remainder by 2
            safe_cap = max(1, (soft - 64) // 2)
            if requested > safe_cap:
                _log.debug(
                    "Requested concurrency %d capped to %d by OS FD limit",
                    requested,
                    safe_cap,
                )
                return safe_cap
            return requested
        except (ValueError, OSError, AttributeError):
            return requested


__all__ = ["ResourceLimiter"]
