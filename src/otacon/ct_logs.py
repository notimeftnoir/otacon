"""Certificate Transparency (CT) log discovery.

Queries public CT log aggregators (Certspotter API and crt.sh) to discover
certificates actively issued in the wild for variants and subdomains of the
target brand.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ._validate import is_valid_domain, normalize_domain

_log = logging.getLogger("otacon.ct_logs")

_CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
_CRTSH_URL = "https://crt.sh/?q={domain}&output=json"


async def fetch_ct_domains(
    target: str,
    timeout: float = 4.0,
    client: httpx.AsyncClient | None = None,
) -> set[str]:
    """Queries CT logs for certificates matching *target*.

    Returns a deduplicated set of valid domains observed in CT logs.
    Degrades gracefully: on timeout or remote error, returns empty set so scans
    never stall.
    """
    domain = normalize_domain(target)
    if not is_valid_domain(domain):
        return set()

    found: set[str] = set()
    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=timeout, headers={"User-Agent": "Otacon-CT/1.0"})

    try:
        # 1. Primary fast source: Certspotter API
        try:
            resp = await http.get(_CERTSPOTTER_URL.format(domain=domain))
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    for item in data[:50]:
                        if isinstance(item, dict):
                            dns_names = item.get("dns_names", [])
                            if isinstance(dns_names, list):
                                for name in dns_names:
                                    _process_candidate(name, domain, found)
        except Exception as exc:
            _log.debug("Certspotter CT lookup failed for %s: %r", domain, exc)

        # 2. Secondary source: crt.sh (if certspotter found few or none)
        if len(found) < 10:
            try:
                resp = await http.get(_CRTSH_URL.format(domain=domain))
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        for item in data[:50]:
                            if isinstance(item, dict):
                                name_val = item.get("name_value", "")
                                if isinstance(name_val, str):
                                    for line in name_val.split("\n"):
                                        _process_candidate(line, domain, found)
            except Exception as exc:
                _log.debug("crt.sh CT lookup failed for %s: %r", domain, exc)

    finally:
        if owns_client:
            await http.aclose()

    return found


def _process_candidate(raw: Any, target: str, out: set[str]) -> None:
    """Cleans and validates a domain candidate from CT logs."""
    if not isinstance(raw, str):
        return
    name = raw.strip().lower()
    if name.startswith("*."):
        name = name[2:]
    name = normalize_domain(name)
    if name and name != target and is_valid_domain(name):
        out.add(name)
