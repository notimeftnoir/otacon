"""Suite-wide fixtures."""

from __future__ import annotations

from unittest.mock import AsyncMock

import aiodns
import pycares
import pytest


@pytest.fixture(autouse=True)
def _no_feed_downloads(monkeypatch, request):
    """Every scan loads threat-intel feeds and asks crt.sh; tests must never
    reach either. test_intel.py / test_ct.py exercise the real code against
    mocked HTTP and opt out with the ``real_feeds`` marker.
    """
    if "real_feeds" in request.keywords:
        return
    monkeypatch.setattr("otacon.intel.load_feeds", AsyncMock(return_value={}))
    monkeypatch.setattr("otacon.ct.recent_certificates", AsyncMock(return_value={}))
    monkeypatch.setattr("otacon.enrich.takedown_contacts", AsyncMock(return_value={}))
    monkeypatch.setattr("otacon.enrich.is_registered", AsyncMock(return_value=None))
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)


@pytest.fixture(autouse=True)
def _no_real_dns(monkeypatch, request):
    """Any DNS query a test did not mock answers NXDOMAIN instead of going out.

    Tests that care patch ``resolver._dns.query_dns`` on the instance, which
    takes precedence; ``-m network`` tests keep the real resolver.
    """
    if "network" in request.keywords:
        return
    nxdomain = aiodns.error.DNSError(pycares.errno.ARES_ENOTFOUND, "Domain name not found")
    monkeypatch.setattr(aiodns.DNSResolver, "query_dns", AsyncMock(side_effect=nxdomain))
