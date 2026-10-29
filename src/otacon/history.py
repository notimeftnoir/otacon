"""On-disk memory of past scans.

A lookalike that appeared last week matters more than one that has been parked
for years, and the only way to know which is which is to have looked before.
Every scan is kept so the console can reopen it without touching the network
and compare it against what is there now.

Storage is deliberately dull: one JSON report per scan, in a directory per
target, in the same format `--json` already writes. No database, no index, no
schema to migrate — a directory you can read, copy, grep and delete.

Location, first match wins:

* ``$OTACON_HOME``
* ``$XDG_DATA_HOME/otacon``
* ``~/.otacon``

Set ``OTACON_HOME`` to move it, or ``OTACON_NO_HISTORY=1`` to keep nothing.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .core.models import ScanReport
from .core.types import RiskLevel
from .utils.validate import is_valid_domain, normalize_domain

# A scan of a busy brand is ~100 KB. Keeping the most recent runs per target
# bounds that at a few megabytes without the operator ever thinking about it.
DEFAULT_KEEP = 30

# Timestamps are the filename, so they must sort lexically as well as
# chronologically and survive a Windows path.
_STAMP = "%Y%m%dT%H%M%SZ"


@dataclass(frozen=True, slots=True)
class ScanRecord:
    """One stored scan, summarised without loading the whole report twice."""

    path: Path
    target: str
    started_at: datetime
    total_permutations: int
    registered: int
    critical: int
    degraded: bool

    @property
    def label(self) -> str:
        """One-line summary for a picker."""
        when = self.started_at.strftime("%Y-%m-%d %H:%M")
        flag = "  ⚠ degraded" if self.degraded else ""
        return f"{when}  ·  {self.registered} registered, {self.critical} critical{flag}"


def history_dir() -> Path:
    """Returns the directory scans are kept in, without creating it."""
    override = os.environ.get("OTACON_HOME")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg).expanduser() / "otacon"
    return Path.home() / ".otacon"


def enabled() -> bool:
    """False when the operator has opted out via ``OTACON_NO_HISTORY``."""
    return os.environ.get("OTACON_NO_HISTORY", "").strip() not in {"1", "true", "yes"}


def _target_dir(target: str, root: Path | None = None) -> Path:
    """Resolves the directory for *target*, refusing anything not a plain domain.

    The target reaches this from a scanned report, so it is attacker-influenced
    in the same way a result filename is: it must never be able to climb out of
    the history directory.
    """
    name = normalize_domain(target)
    if not is_valid_domain(name):
        raise ValueError(f"refusing to store history for invalid target: {target!r}")
    base = (root or history_dir()).expanduser()
    resolved = (base / name).resolve()
    if resolved != base.resolve() / name:
        raise ValueError(f"refusing to store history outside {base}: {target!r}")
    return resolved


def save(report: ScanReport, root: Path | None = None, keep: int = DEFAULT_KEEP) -> Path | None:
    """Writes *report* into the history and prunes old runs. None when disabled.

    The directory and file are created owner-only: a scan reveals which brand
    somebody is watching and which lookalikes are live, which is not something
    to leave world-readable on a shared host.
    """
    if not enabled():
        return None
    directory = _target_dir(report.target, root)
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(stat.S_IRWXU)

    stamp = report.started_at.astimezone(UTC).strftime(_STAMP)
    path = directory / f"{stamp}.json"
    # The stamp is only accurate to the second, so two runs started in the same
    # one landed on the same filename and the second quietly replaced the first.
    # Everything here exists to keep every scan, so suffix rather than clobber.
    suffix = 1
    while path.exists():
        path = directory / f"{stamp}-{suffix}.json"
        suffix += 1
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    prune(report.target, keep=keep, root=root)
    return path


def targets(root: Path | None = None) -> list[str]:
    """Every target with at least one stored scan, alphabetically."""
    base = (root or history_dir()).expanduser()
    if not base.is_dir():
        return []
    return sorted(d.name for d in base.iterdir() if d.is_dir() and any(d.glob("*.json")))


def scans(target: str, root: Path | None = None, limit: int = DEFAULT_KEEP) -> list[ScanRecord]:
    """Stored scans for *target*, newest first. Unreadable files are skipped."""
    try:
        directory = _target_dir(target, root)
    except ValueError:
        return []
    if not directory.is_dir():
        return []
    records: list[ScanRecord] = []
    for path in sorted(directory.glob("*.json"), reverse=True)[:limit]:
        record = _summarise(path)
        if record is not None:
            records.append(record)
    return records


def latest(target: str, root: Path | None = None) -> ScanReport | None:
    """The most recent stored scan for *target*, or None."""
    found = scans(target, root=root, limit=1)
    return load(found[0].path) if found else None


def load(path: Path) -> ScanReport:
    """Reads a stored report back."""
    return ScanReport.model_validate_json(Path(path).read_text(encoding="utf-8"))


def prune(target: str, keep: int = DEFAULT_KEEP, root: Path | None = None) -> int:
    """Deletes all but the *keep* newest scans for *target*. Returns how many went."""
    directory = _target_dir(target, root)
    if not directory.is_dir():
        return 0
    stored = sorted(directory.glob("*.json"), reverse=True)
    removed = 0
    for path in stored[max(keep, 0) :]:
        path.unlink(missing_ok=True)
        removed += 1
    return removed


def forget(target: str, root: Path | None = None) -> int:
    """Deletes every stored scan for *target*. Returns how many files went."""
    directory = _target_dir(target, root)
    if not directory.is_dir():
        return 0
    removed = 0
    for path in directory.glob("*.json"):
        path.unlink(missing_ok=True)
        removed += 1
    directory.rmdir()
    return removed


def _summarise(path: Path) -> ScanRecord | None:
    """Reads one stored file into a record, or None when it cannot be parsed."""
    try:
        report = load(path)
    except Exception:
        # A truncated or hand-edited file must not take the whole picker down.
        return None
    registered = report.registered
    return ScanRecord(
        path=path,
        target=report.target,
        started_at=report.started_at,
        total_permutations=report.total_permutations,
        registered=len(registered),
        critical=sum(1 for r in registered if r.risk_level is RiskLevel.CRITICAL),
        degraded=report.degraded,
    )


__all__ = [
    "DEFAULT_KEEP",
    "ScanRecord",
    "enabled",
    "forget",
    "history_dir",
    "latest",
    "load",
    "prune",
    "save",
    "scans",
    "targets",
]
