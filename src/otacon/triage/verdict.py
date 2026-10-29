"""The scan's answer to "am I in trouble", in words a non-specialist can act on.

`otacon scan` has always printed this as a verdict card. The triage console —
which is what plain `otacon` opens, and therefore the surface most people
actually meet — printed none of it and dropped the reader straight into a
table of a few hundred rows.

So the verdict moved here, where both surfaces reach it. Nothing is recomputed:
the console reporter's `_headline` is now a thin adapter over `verdict()`, and
the overview screen renders the same three sentences.

The wording is deliberately plain. "4 lookalikes of paypal.com look dangerous"
is a sentence anybody can act on; "4 CRITICAL" is a sentence you have to have
been taught.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from ..core.models import DomainResult, ScanReport
from ..core.types import RiskLevel
from ..ui.copy import FLAGS


@dataclass(frozen=True)
class Verdict:
    """What the whole scan amounts to."""

    tone: str
    """Semantic style name — ``ok``, ``warn`` or ``danger``."""

    level: RiskLevel
    """Worst level among registered results; SAFE when nothing is registered."""

    headline: str
    explanation: str

    degraded: bool
    """True when the result is not a complete picture, for any reason.

    A scan the operator stopped and a scan whose resolver failed both leave a
    short result list that reads exactly like a quiet one, so neither may be
    reported as an all-clear.
    """

    @property
    def marker(self) -> str:
        """The glyph a surface should put in front of the headline.

        Kept out of the headline itself so each surface can degrade it: a
        verdict carrying a literal U+26A0 cannot be rendered on a terminal
        that has no such character, and the sentence is the part that matters.
        """
        return {"danger": "⚠", "warn": "●", "ok": "✓"}[self.tone]


class ChangeKind(str, Enum):
    """What sort of movement a change is.

    Carried alongside the sentence rather than inferred from it: a screen that
    groups these by matching on prose breaks the first time the wording is
    improved.
    """

    REGISTERED = "newly registered"
    ESCALATED = "risk rose"
    FOUND = "found since last time"
    GONE = "no longer registered"


@dataclass(frozen=True)
class Change:
    """One thing that moved since the previous scan of this target."""

    domain: str
    detail: str
    kind: ChangeKind = ChangeKind.REGISTERED


@dataclass(frozen=True)
class Delta:
    """What changed since the previous stored scan."""

    since: datetime
    changes: list[Change]

    @property
    def quiet(self) -> bool:
        """True when nothing worth reporting moved."""
        return not self.changes


def verdict(report: ScanReport) -> Verdict:
    """The scan's headline, explanation and tone."""
    registered = report.registered
    target = report.target
    n = len(registered)
    plural = "s" if n != 1 else ""

    if report.cancelled:
        # The operator knows they stopped it; what they must not be told is
        # that what came back is the whole picture.
        checked = len(report.results)
        return Verdict(
            tone="warn",
            level=max(
                (r.risk_level for r in registered),
                key=lambda lv: lv.rank,
                default=RiskLevel.SAFE,
            ),
            headline=(
                f"Stopped early: {checked} of {report.total_permutations} "
                f"lookalikes of {target} were checked"
            ),
            explanation=(
                f"{n} registered one{plural} turned up in what was checked. The rest were "
                "never looked at, so this is not a clean bill of health — run it again to "
                "finish."
            ),
            degraded=True,
        )

    if report.degraded:
        # A broken resolver and a clean brand produce the same empty result, so
        # this case must never be reported as an all-clear. Name the layer that
        # actually failed: DNS and the probes above it degrade independently.
        if report.probe_failures and report.probe_failure_ratio >= report.dns_failure_ratio:
            pct = round(report.probe_failure_ratio * 100)
            what = f"{pct}% of checks on {target} could not be completed"
            why = (
                f"{report.probe_failures} of {len(report.results)} lookalikes raised an error "
                "instead of answering"
            )
        else:
            pct = round(report.dns_failure_ratio * 100)
            what = f"{pct}% of DNS lookups for {target} failed"
            why = f"{report.dns_failures} of {report.dns_queries} lookups could not be answered"
        return Verdict(
            tone="warn",
            level=RiskLevel.SAFE,
            headline=f"Inconclusive: {what}",
            explanation=(
                f"{why}, so a domain shown as unregistered may simply not have been checked. "
                "Re-run with --debug to see why, and treat these results as incomplete."
            ),
            degraded=True,
        )

    if not registered:
        return Verdict(
            tone="ok",
            level=RiskLevel.SAFE,
            headline=(
                f"All clear: none of the {report.total_permutations} lookalikes of "
                f"{target} are registered"
            ),
            explanation=(
                "Nobody has registered a domain that imitates yours. New ones appear every day, "
                "so run this again from time to time."
            ),
            degraded=False,
        )

    worst = max(registered, key=lambda r: r.risk_level.rank).risk_level
    if worst.rank >= RiskLevel.HIGH.rank:
        k = sum(1 for r in registered if r.risk_level.rank >= RiskLevel.HIGH.rank)
        return Verdict(
            tone="danger",
            level=worst,
            headline=(
                f"{k} lookalike{'s' if k != 1 else ''} of {target} "
                f"look{'' if k != 1 else 's'} dangerous"
            ),
            explanation=(
                "Registered and set up like a real website or mail server. "
                "Start with the top rows of the table."
            ),
            degraded=False,
        )

    if worst.rank >= RiskLevel.LOW.rank:
        return Verdict(
            tone="warn",
            level=worst,
            headline=f"{n} registered lookalike{plural} of {target}, nothing urgent",
            explanation=(
                "They exist, but show few signs of being used for attacks yet. Worth a look."
            ),
            degraded=False,
        )

    return Verdict(
        tone="ok",
        level=worst,
        headline=f"{n} registered lookalike{plural} of {target}, all look harmless",
        explanation="Parked pages or redirects back to your own site.",
        degraded=False,
    )


def reasons(result: DomainResult) -> str:
    """Why this row is worth attention, as plain words rather than markers.

    The table has four characters per flag; here there is room to say
    "cloned favicon" instead of FAVICON, so the overview can be read by
    someone who has not opened the glossary.
    """
    found: list[str] = []
    if result.dnsbl_listed:
        found.append(FLAGS["dnsbl"].long)
    if result.favicon_matches_target:
        found.append(FLAGS["favicon"].long)
    if result.has_login_form:
        found.append(FLAGS["login"].long)
    if result.has_mx and result.is_mail_spoofable:
        found.append(FLAGS["spoof"].long)
    if result.is_sinkhole:
        found.append(FLAGS["sinkhole"].long)
    elif result.is_parked:
        found.append(FLAGS["parked"].long)
    if result.is_likely_defensive:
        found.append(FLAGS["defensive"].long)
    if found:
        return ", ".join(found)
    # Registered and resolving but carrying none of the flags: say what it is
    # rather than leaving the line blank.
    return "registered and resolving" if result.resolves else "registered"


def worst_first(report: ScanReport, limit: int = 3) -> list[DomainResult]:
    """The rows worth opening first, worst score first."""
    ranked = sorted(report.registered, key=lambda r: (-r.risk_score, r.domain))
    return [r for r in ranked if r.risk_score > 0][:limit]


def delta(previous: ScanReport, current: ScanReport) -> Delta:
    """What moved between two scans of the same target.

    Deliberately narrower than :func:`otacon.diff.compute_diff`, which backs the
    `diff` command and reports every field that moved — including an IP change,
    which fires on any CDN-hosted domain and would bury the two lines that
    matter. This answers only the reader's question: what is newly registered,
    what got worse, and what went away.
    """
    before = {r.domain: r for r in previous.results}
    changes: list[Change] = []

    for r in current.results:
        was = before.get(r.domain)
        if was is None:
            if r.is_registered:
                changes.append(Change(r.domain, "found since last time", ChangeKind.FOUND))
            continue
        if r.is_registered and not was.is_registered:
            changes.append(Change(r.domain, "newly registered", ChangeKind.REGISTERED))
        elif r.is_registered and r.risk_level.rank > was.risk_level.rank:
            changes.append(
                Change(
                    r.domain,
                    f"risk rose {was.risk_level.value} to {r.risk_level.value}",
                    ChangeKind.ESCALATED,
                )
            )

    now = {r.domain for r in current.results if r.is_registered}
    for domain, was in before.items():
        if was.is_registered and domain not in now:
            changes.append(Change(domain, "no longer registered", ChangeKind.GONE))

    changes.sort(key=lambda c: c.domain)
    return Delta(since=previous.started_at, changes=changes)


def baseline(report: ScanReport) -> ScanReport | None:
    """The stored scan to compare *report* against, or None if it is the first.

    Skips any stored run that is this one. A scan is written to history the
    moment it finishes, so the newest record is usually the report already on
    screen, and comparing it with itself would report that nothing ever
    changes.
    """
    from .. import history

    try:
        for record in history.scans(report.target):
            if record.started_at != report.started_at:
                return history.load(record.path)
    except Exception:
        # History is a convenience; an unreadable store must not cost the
        # operator the screen they asked for.
        return None
    return None


__all__ = [
    "Change",
    "ChangeKind",
    "Delta",
    "Verdict",
    "baseline",
    "delta",
    "reasons",
    "verdict",
    "worst_first",
]
