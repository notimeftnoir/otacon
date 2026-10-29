"""What Otacon remembers between runs.

Scan history is a directory of reports — what was found. This is the other
half: what the operator decided. A domain waved through because it is theirs
should stay waved through; a brand worth watching should still be worth
watching next week.

Storage is as dull as the history beside it: JSON under the same root, one
file for the settings and one per target. No database, no migrations — a
directory you can read, copy, grep and delete.

    <OTACON_HOME>/config/settings.json
    <OTACON_HOME>/config/targets/<domain>.json

Nothing here raises on bad input. A hand-edited file, a stale key, a theme
name that no longer exists: each falls back to the default rather than
costing somebody a scan. Configuration is a convenience, and a convenience
that can refuse to start is not one.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .history import history_dir
from .utils.validate import is_valid_domain, normalize_domain

# A bare label is not a valid domain, so these can never collide with a
# target's own directory under the same root.
_CONFIG = "config"
_TARGETS = "targets"


def config_dir(root: Path | None = None) -> Path:
    """The directory settings live in, without creating it."""
    return (root or history_dir()).expanduser() / _CONFIG


def enabled() -> bool:
    """False when the operator has opted out via ``OTACON_NO_CONFIG``."""
    return os.environ.get("OTACON_NO_CONFIG", "").strip() not in {"1", "true", "yes"}


@dataclass
class Settings:
    """Preferences that apply to every scan."""

    theme: str = "midnight"
    ascii: bool = False
    preset: str = "thorough"
    fail_on: str | None = None


@dataclass
class TargetConfig:
    """What the operator decided about one brand."""

    allowed: list[str] = field(default_factory=list)
    """Domains to leave out of future scans — usually registrations of their own."""

    watched: bool = False
    """Whether this target is on the watchlist."""


def _write(path: Path, payload: dict[str, object]) -> None:
    """Writes *payload* owner-only, creating the directory.

    Owner-only for the same reason history is: a watchlist says which brands
    somebody is monitoring, and an allow-list says which lookalikes they have
    decided to ignore. Neither belongs to every account on a shared host.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(stat.S_IRWXU)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def _read(path: Path) -> dict[str, object]:
    """Reads a config file, or an empty mapping when it cannot be read."""
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def settings(root: Path | None = None) -> Settings:
    """The stored settings, with anything unreadable falling back to defaults."""
    if not enabled():
        return Settings()
    raw = _read(config_dir(root) / "settings.json")
    base = Settings()
    theme = raw.get("theme")
    preset = raw.get("preset")
    fail_on = raw.get("fail_on")
    return Settings(
        theme=theme if isinstance(theme, str) else base.theme,
        ascii=bool(raw.get("ascii", base.ascii)),
        preset=preset if isinstance(preset, str) else base.preset,
        fail_on=fail_on if isinstance(fail_on, str) else None,
    )


def save_settings(value: Settings, root: Path | None = None) -> Path | None:
    """Stores the settings. None when configuration is switched off."""
    if not enabled():
        return None
    path = config_dir(root) / "settings.json"
    _write(path, asdict(value))
    return path


def _target_path(target: str, root: Path | None = None) -> Path:
    """Resolves one target's config file, refusing anything not a plain domain.

    The target reaches this from a scanned report, so it is attacker-influenced
    in the same way a result filename is: it must never climb out of the
    config directory.
    """
    name = normalize_domain(target)
    if not is_valid_domain(name):
        raise ValueError(f"refusing to store config for invalid target: {target!r}")
    base = config_dir(root) / _TARGETS
    resolved = (base / f"{name}.json").resolve()
    if resolved.parent != base.resolve():
        raise ValueError(f"refusing to store config outside {base}: {target!r}")
    return resolved


def target(name: str, root: Path | None = None) -> TargetConfig:
    """What is stored for *name*, or the defaults."""
    if not enabled():
        return TargetConfig()
    try:
        raw = _read(_target_path(name, root))
    except ValueError:
        return TargetConfig()
    stored = raw.get("allowed")
    allowed = sorted({d for d in stored if isinstance(d, str)}) if isinstance(stored, list) else []
    return TargetConfig(allowed=allowed, watched=bool(raw.get("watched", False)))


def save_target(name: str, value: TargetConfig, root: Path | None = None) -> Path | None:
    """Stores *value* for *name*. None when configuration is switched off."""
    if not enabled():
        return None
    try:
        path = _target_path(name, root)
    except ValueError:
        return None
    _write(path, {"allowed": sorted(set(value.allowed)), "watched": value.watched})
    return path


def allow(name: str, *domains: str, root: Path | None = None) -> TargetConfig:
    """Adds *domains* to the target's allow-list and stores it."""
    current = target(name, root)
    merged = sorted(set(current.allowed) | {normalize_domain(d) for d in domains if d})
    updated = TargetConfig(allowed=merged, watched=current.watched)
    save_target(name, updated, root)
    return updated


def unallow(name: str, *domains: str, root: Path | None = None) -> TargetConfig:
    """Removes *domains* from the target's allow-list and stores it."""
    current = target(name, root)
    drop = {normalize_domain(d) for d in domains if d}
    updated = TargetConfig(
        allowed=[d for d in current.allowed if d not in drop], watched=current.watched
    )
    save_target(name, updated, root)
    return updated


def set_watched(name: str, watching: bool, root: Path | None = None) -> TargetConfig:
    """Puts *name* on the watchlist, or takes it off."""
    current = target(name, root)
    updated = TargetConfig(allowed=current.allowed, watched=watching)
    save_target(name, updated, root)
    return updated


def watched(root: Path | None = None) -> list[str]:
    """Every target on the watchlist, alphabetically."""
    if not enabled():
        return []
    base = config_dir(root) / _TARGETS
    if not base.is_dir():
        return []
    out = [p.stem for p in sorted(base.glob("*.json")) if target(p.stem, root).watched]
    return out


__all__ = [
    "Settings",
    "TargetConfig",
    "allow",
    "config_dir",
    "enabled",
    "save_settings",
    "save_target",
    "set_watched",
    "settings",
    "target",
    "unallow",
    "watched",
]
