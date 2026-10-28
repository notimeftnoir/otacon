"""Shared fixtures.

The suite runs the real `execute_scan` in several places, and that persists its
report through `otacon.history`. Without this the tests write fixture domains
(`evil-twin.com`, `clean.com`, `a.com`) into the developer's own `~/.otacon`.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolate_scan_history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Points scan history at a temporary directory for every test.

    Autouse and unconditional: a test that happens to reach a code path writing
    history should not have to know that it does.
    """
    root = tmp_path / "otacon-history"
    monkeypatch.setenv("OTACON_HOME", str(root))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.delenv("OTACON_NO_HISTORY", raising=False)
    yield root
