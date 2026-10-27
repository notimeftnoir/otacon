"""Monitoring: what changed since the last scan, and who to tell.

``otacon watch`` scans once, compares against the state saved by the
previous run and reports only the differences, so it can run from cron, the
Windows Task Scheduler or a scheduled GitHub Action without re-alerting on
the same lookalikes every time. The first run of a target only records a
baseline.

State is a small SQLite file, one row per registered variant and per
discovered host, keyed by target so one file can watch several brands.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .models import DomainResult, ScanReport

_log = logging.getLogger("otacon.watch")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (target TEXT NOT NULL, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS variants (
    target TEXT NOT NULL,
    domain TEXT NOT NULL,
    signals TEXT NOT NULL,      -- JSON list: confirmed signals, kept for good
    pending TEXT NOT NULL,      -- JSON list: seen last run, not yet confirmed
    last_seen TEXT NOT NULL,
    missed INTEGER NOT NULL,    -- consecutive runs it was missing
    PRIMARY KEY (target, domain)
);
CREATE TABLE IF NOT EXISTS discoveries (
    target TEXT NOT NULL,
    host TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (target, host)
);
"""


def default_state_path() -> Path:
    """Per-user data file: %LOCALAPPDATA% on Windows, $XDG_DATA_HOME elsewhere."""
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        base = Path(os.environ["LOCALAPPDATA"])
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "otacon" / "watch.sqlite"


@dataclass(frozen=True)
class Event:
    """One change worth telling someone about."""

    kind: str  # "new" | "escalated" | "gone" | "discovered"
    domain: str
    detail: str
    level: str | None = None


def signals(r: DomainResult) -> set[str]:
    """The observable facts about a variant whose appearance is news."""
    out = {
        name
        for name, on in (
            ("dns", r.resolves),
            ("mx", r.has_mx),
            ("ssl", r.has_ssl),
            ("spf", r.has_spf),
            ("reported", bool(r.intel_sources)),
        )
        if on
    }
    if r.http_status is not None and 200 <= r.http_status < 300:
        out.add("web")
    return out


# Signals that do not flap: a DNS answer (after retries) and a feed listing.
_RELIABLE = frozenset({"dns", "reported"})

_SIGNAL_WORDS = {
    "dns": "now resolves",
    "mx": "mail server added",
    "ssl": "certificate added",
    "spf": "SPF published",
    "web": "website went live",
    "reported": "reported as phishing",
}


class State:
    """The previous run's view of each target, in SQLite."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        self._db.close()

    def has_baseline(self, target: str) -> bool:
        return (
            self._db.execute("SELECT 1 FROM runs WHERE target = ?", (target,)).fetchone()
            is not None
        )

    def _variants(self, target: str) -> dict[str, tuple[set[str], set[str], int]]:
        """{domain: (confirmed signals, signals awaiting confirmation, misses in a row)}."""
        return {
            domain: (set(json.loads(sig)), set(json.loads(pending)), missed)
            for domain, sig, pending, missed in self._db.execute(
                "SELECT domain, signals, pending, missed FROM variants WHERE target = ?",
                (target,),
            )
        }

    def diff(self, report: ScanReport) -> list[Event]:
        """Events between the stored state and *report*; does not save anything.

        Probes flap: a TLS handshake or HTTP request to a slow host fails in
        some runs and not others. So a probe signal escalates only once it is
        seen in two runs in a row, and is then remembered for good; DNS and
        feed listings are reliable and escalate at once. A variant must be
        missing two runs in a row to be reported gone.
        """
        target = report.target
        before = self._variants(target)
        events: list[Event] = []
        now = {r.domain: r for r in report.registered}
        for domain, r in sorted(now.items(), key=lambda kv: -kv[1].risk_score):
            level = r.risk_level.value
            if domain not in before:
                events.append(Event("new", domain, f"registered, risk {r.risk_score}", level))
                continue
            seen, pending, _ = before[domain]
            current = signals(r)
            added = sorted(((current & pending) | (current & _RELIABLE)) - seen)
            if added:
                words = ", ".join(_SIGNAL_WORDS[s] for s in added)
                events.append(Event("escalated", domain, f"{words} (risk {r.risk_score})", level))
        # Silence is not removal: a variant DNS could not answer for stays put.
        unknown = {r.domain for r in report.inconclusive}
        for domain in sorted(set(before) - set(now) - unknown):
            if before[domain][2] >= 1:
                events.append(Event("gone", domain, "no longer registered or reachable"))
        seen_hosts = {
            h
            for (h,) in self._db.execute("SELECT host FROM discoveries WHERE target = ?", (target,))
        }
        for d in report.discovered:
            if d.host not in seen_hosts:
                events.append(Event("discovered", d.host, "seen in " + ", ".join(d.sources)))
        return events

    def save(self, report: ScanReport) -> None:
        """Folds *report* into the stored view of report.target (see diff)."""
        target, at = report.target, datetime.now(UTC).isoformat(timespec="seconds")
        baseline = not self.has_baseline(target)
        before = self._variants(target)
        now = {r.domain: r for r in report.registered}
        unknown = {r.domain for r in report.inconclusive}
        with self._db:
            for domain in set(before) - set(now) - unknown:
                if before[domain][2] >= 1:  # second miss in a row: reported gone, forget it
                    self._db.execute(
                        "DELETE FROM variants WHERE target = ? AND domain = ?", (target, domain)
                    )
                else:
                    self._db.execute(
                        "UPDATE variants SET missed = 1 WHERE target = ? AND domain = ?",
                        (target, domain),
                    )
            for domain, r in now.items():
                current = signals(r)
                if baseline or domain not in before:
                    # What a variant shows when first met is its starting point, not news.
                    seen, pending = current, set()
                else:
                    seen, pending, _ = before[domain]
                    seen = seen | (current & pending) | (current & _RELIABLE)
                    pending = current - seen
                self._db.execute(
                    "INSERT OR REPLACE INTO variants VALUES (?, ?, ?, ?, ?, ?)",
                    (target, domain, json.dumps(sorted(seen)), json.dumps(sorted(pending)), at, 0),
                )
            self._db.executemany(
                "INSERT OR IGNORE INTO discoveries VALUES (?, ?, ?)",
                [(target, d.host, at) for d in report.discovered],
            )
            self._db.execute("INSERT INTO runs VALUES (?, ?)", (target, at))


def defang(domain: str) -> str:
    """exampel.com -> exampel[.]com, so chat apps do not turn it into a link."""
    return domain.replace(".", "[.]")


def summary(target: str, events: list[Event]) -> str:
    """Plain-text alert body, domains defanged."""
    lines = [f"Otacon: {len(events)} change(s) for {defang(target)}"]
    for e in events:
        level = f" [{e.level}]" if e.level else ""
        lines.append(f"- {e.kind.upper()}{level} {defang(e.domain)}: {e.detail}")
    return "\n".join(lines)


def _payload(url: str, target: str, events: list[Event]) -> dict[str, object]:
    """Body shaped for the service behind *url*; generic JSON otherwise."""
    host = (urlsplit(url).hostname or "").lower()
    text = summary(target, events)
    if host.endswith("discord.com") or host.endswith("discordapp.com"):
        return {"content": text[:2000]}  # Discord's message limit
    if host == "hooks.slack.com" or host.endswith("webhook.office.com"):
        return {"text": text}
    return {"target": target, "events": [asdict(e) for e in events], "text": text}


async def notify(client: httpx.AsyncClient, url: str, target: str, events: list[Event]) -> bool:
    """POSTs the alert to one webhook; True when it was accepted."""
    try:
        resp = await client.post(url, json=_payload(url, target, events), timeout=15.0)
    except httpx.HTTPError as exc:
        _log.debug("webhook %s failed: %r", urlsplit(url).hostname, exc)
        return False
    return resp.is_success
