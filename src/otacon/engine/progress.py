"""What a running scan reports back to whatever is drawing it.

The scan used to hand its front-end two integers, which was enough for a bar
and nothing else. The console reporter made up the difference by rendering its
own live table from inside the engine; the triage console, which had no way to
do that, showed a bar and a count — so the surface people actually use told
them less than the one they pipe to a file.

One structure now carries everything either front-end needs, including the
stage. That matters most before the first domain is checked: building the
candidate list and querying Certificate Transparency happen before the counter
can move at all, so a scan with CT enabled used to sit on a motionless bar for
several seconds with nothing to say for itself.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.models import DomainResult
from ..core.types import ScanPhase


@dataclass(frozen=True, slots=True)
class ScanProgress:
    """A snapshot of a scan in flight."""

    phase: ScanPhase
    done: int = 0
    total: int = 0
    hits: int = 0
    """Registered lookalikes found so far."""

    dangerous: int = 0
    """Of those, the ones at high or critical."""

    dns_queries: int = 0
    dns_failures: int = 0
    latest: DomainResult | None = None
    """The result just scored, when it was a registered one. Feeds the live list."""

    @property
    def fraction(self) -> float:
        """How far through the checking stage, 0..1."""
        return self.done / self.total if self.total else 0.0

    @property
    def dns_failure_ratio(self) -> float:
        """Share of DNS lookups that failed rather than answering."""
        return self.dns_failures / self.dns_queries if self.dns_queries else 0.0


__all__ = ["ScanProgress"]
