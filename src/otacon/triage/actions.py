"""Re-probing a single result after the scan.

What remains of the triage actions once the console owns the interaction: the
network half, with no prompts and no console attached, so the caller decides how
to report it.
"""

from __future__ import annotations

from ..core.models import DomainResult, Permutation
from ..net.resolver import Resolver
from ..scoring import engine as scoring


async def rescan_result(result: DomainResult, target: str, check_http: bool = True) -> DomainResult:
    """Re-probes one variant and returns it rescored.

    A result goes stale the moment it is printed — a domain that was parked an
    hour ago may be serving a login form now — so the console can ask for any
    single row to be checked again without repeating the whole scan.
    """
    perm = Permutation(domain=result.domain, kind=result.kind, note=result.note)
    async with Resolver(check_http=check_http, target=target) as resolver:
        raw = await resolver.check_one(perm)
        return scoring.score(raw, target, target_title=resolver.target_title)


__all__ = ["rescan_result"]
