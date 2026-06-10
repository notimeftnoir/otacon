"""Baseline persistence for watch mode.

Saves the set of registered domain variants (with their scores and signals)
to ``~/.otacon/<domain>.json`` so subsequent runs can diff against it.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .models import DomainResult

_log = logging.getLogger("otacon.state")
_OTACON_DIR = ".otacon"
_SAFE_DOMAIN_RE = re.compile(r"[^\w.\-]")


def _safe_filename(domain: str) -> str:
    """Strips characters that could cause path traversal (e.g. '/', '\\', '..').

    Only word chars, dots, and hyphens survive — every valid FQDN stays intact.
    """
    return _SAFE_DOMAIN_RE.sub("_", domain)


def baseline_path(domain: str, home: Path | None = None) -> Path:
    """Returns the path to the baseline file for *domain*."""
    return (home or Path.home()) / _OTACON_DIR / f"{_safe_filename(domain)}.json"


def load_baseline(domain: str, home: Path | None = None) -> dict[str, dict[str, object]] | None:
    """Loads the baseline for *domain*.

    Returns a ``{domain_variant: snapshot_dict}`` mapping, or ``None`` when
    there is no saved baseline or the file cannot be parsed.
    """
    path = baseline_path(domain, home=home)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        registered = data.get("registered")
        if not isinstance(registered, dict):
            return None
        return registered
    except (json.JSONDecodeError, OSError) as exc:
        # Corrupt/unreadable baseline → treat as "no prior data" rather than crash.
        _log.debug("could not load baseline %s: %r", path, exc)
        return None


def save_baseline(
    domain: str,
    results: list[DomainResult],
    home: Path | None = None,
) -> None:
    """Persists *results* as the new baseline for *domain*.

    Only registered variants are stored — unregistered ones carry no signal
    worth tracking between runs.
    """
    path = baseline_path(domain, home=home)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "target": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "registered": {
            r.domain: r.model_dump(mode="json")
            for r in results
            if r.is_registered
        },
    }
    # Write-then-rename so a crash mid-write can't leave a corrupt baseline —
    # in watch mode that file is the only memory between runs.
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp, path)
