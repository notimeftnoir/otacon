"""Suite-wide fixtures."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest


@pytest.fixture(autouse=True)
def _no_feed_downloads(monkeypatch, request):
    """Every scan loads threat-intel feeds; tests must never download them.

    tests/test_intel.py exercises the real loader against mocked HTTP and opts
    out with the ``real_feeds`` marker.
    """
    if "real_feeds" in request.keywords:
        return
    monkeypatch.setattr("otacon.intel.load_feeds", AsyncMock(return_value={}))
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
