"""Reporter protocol definition."""

from __future__ import annotations

from typing import Protocol

from ..core.models import ScanReport


class BaseReporter(Protocol):
    """Protocol for all scan report formatters."""

    def render(self, report: ScanReport) -> str:
        """Renders scan report to formatted string."""
        ...


__all__ = ["BaseReporter"]
