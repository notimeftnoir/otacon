"""Operating system resource and file descriptor limit management."""

from __future__ import annotations

import logging
import sys

_log = logging.getLogger("otacon.engine.pool")

# `resource` is Unix-only. The import has to be guarded rather than merely wrapped
# in the try/except below: on Windows a module-level `import resource` raises
# ModuleNotFoundError, which took down every importer of this module — including
# engine.scanner, and so the whole CLI.
if sys.platform != "win32":
    import resource

# Reserve descriptors for stdio, logs and internal tasks before dividing what is
# left between the two sockets a probe can hold open at once.
_FD_RESERVE = 64


class ResourceLimiter:
    """Manages adaptive concurrency bounded by OS file descriptor limits."""

    @staticmethod
    def compute_safe_concurrency(requested: int) -> int:
        """Calculates bounded concurrency preventing EMFILE (Too many open files)."""
        # The Unix body sits inside the platform guard rather than behind an early
        # return so that a Windows type-check excludes it along with the import.
        # Windows exposes no per-process descriptor ceiling to query; its sockets
        # are bounded by memory, well above any concurrency we would request.
        if sys.platform != "win32":
            try:
                soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            except (ValueError, OSError, AttributeError):
                return requested
            safe_cap = max(1, (int(soft) - _FD_RESERVE) // 2)
            if requested > safe_cap:
                _log.debug(
                    "Requested concurrency %d capped to %d by OS FD limit",
                    requested,
                    safe_cap,
                )
                return safe_cap
        return requested


__all__ = ["ResourceLimiter"]
