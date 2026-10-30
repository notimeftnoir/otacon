"""Certificate Transparency (CT) log discovery.

Finds lookalikes the permutation rules cannot guess — ``allegro-zwroty.pl``,
``mbank-weryfikacja.com`` — by asking crt.sh for every certificate whose names
contain the brand label.

The target's *own* certificates are fetched as well, but only to exclude what
they cover. Every name sharing a certificate with the target was put there by
the target's owner, so it is their infrastructure, not an impersonation. Used
the other way round, as this module once did, it reported ``facebook.net`` and
``messenger.com`` as lookalikes of ``facebook.com`` and scored them HIGH.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ._validate import is_valid_domain, normalize_domain
from .net.http import USER_AGENT
from .permutations.rules import split_domain

_log = logging.getLogger("otacon.ct_logs")

# crt.sh answers %label% searches in seconds for most brands, but it is a free
# service under constant load; give it room before calling it unavailable.
_CRTSH_TIMEOUT = 30.0
_CRTSH_URL = "https://crt.sh/?q=%25{label}%25&output=json&exclude=expired"
_CERTSPOTTER_URL = (
    "https://api.certspotter.com/v1/issuances"
    "?domain={domain}&include_subdomains=true&expand=dns_names"
)
# %g% matches most of the internet. Below this length a label search is noise.
_MIN_LABEL = 4
# Each candidate costs a full probe; a brand with a long CT tail must not turn
# one scan into thousands of requests.
_MAX_CANDIDATES = 100


def registrable(name: str) -> str:
    """Collapses a hostname to the domain someone registered (eTLD+1).

    ``login.allegro-zwroty.pl`` → ``allegro-zwroty.pl``. Multi-label suffixes
    come from the same list the permutation rules use; one that is missing
    there collapses one label too far, which only costs a missed candidate.
    """
    label, tld = split_domain(name)
    if not tld:
        return name
    return f"{label.rsplit('.', 1)[-1]}.{tld}"


def _names(raw: Any) -> set[str]:
    """Valid, normalised hostnames from one CT field (a name or a newline list)."""
    if isinstance(raw, list):
        raw = "\n".join(str(x) for x in raw)
    if not isinstance(raw, str):
        return set()
    out = set()
    for line in raw.split("\n"):
        name = normalize_domain(line.strip().lower().removeprefix("*."))
        if name and is_valid_domain(name):
            out.add(name)
    return out


async def _own_domains(http: httpx.AsyncClient, target: str) -> set[str]:
    """Registrable domains that share a certificate with *target*."""
    resp = await http.get(_CERTSPOTTER_URL.format(domain=target))
    data = resp.json() if resp.status_code == 200 else []
    own = {target}
    for item in data if isinstance(data, list) else []:
        if isinstance(item, dict):
            own |= {registrable(n) for n in _names(item.get("dns_names"))}
    return own


async def _label_matches(http: httpx.AsyncClient, label: str) -> set[str]:
    """Registrable domains from every unexpired certificate naming *label*."""
    resp = await http.get(_CRTSH_URL.format(label=label), timeout=_CRTSH_TIMEOUT)
    data = resp.json() if resp.status_code == 200 else []
    found: set[str] = set()
    for item in data if isinstance(data, list) else []:
        if isinstance(item, dict):
            found |= {registrable(n) for n in _names(item.get("name_value"))}
    # crt.sh matches the label anywhere, including in a subdomain of an
    # unrelated site; only a registered name carrying the brand counts.
    return {d for d in found if label in d}


async def fetch_ct_domains(
    target: str,
    timeout: float = 10.0,
    client: httpx.AsyncClient | None = None,
) -> set[str]:
    """Lookalike domains of *target* seen in Certificate Transparency logs.

    Returns registrable domains that carry the brand label, minus the target's
    own infrastructure. Degrades to an empty set on any remote failure so a
    scan never stalls on a third-party service.
    """
    domain = normalize_domain(target)
    if not is_valid_domain(domain):
        return set()
    label = split_domain(domain)[0].rsplit(".", 1)[-1]
    if len(label) < _MIN_LABEL:
        _log.debug("CT discovery skipped for %s: label %r too short to search", domain, label)
        return set()

    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=timeout, headers={"User-Agent": USER_AGENT})
    try:
        try:
            candidates = await _label_matches(http, label)
        except Exception as exc:
            _log.debug("crt.sh CT lookup failed for %s: %r", label, exc)
            return set()
        if not candidates:
            return set()
        try:
            own = await _own_domains(http, domain)
        except Exception as exc:
            # Without the exclusion list the candidates still carry the brand
            # label; the operator's allow-list covers the brand's own names.
            _log.debug("Certspotter CT lookup failed for %s: %r", domain, exc)
            own = {domain}
    finally:
        if owns_client:
            await http.aclose()

    return set(sorted(candidates - own)[:_MAX_CANDIDATES])


__all__ = ["fetch_ct_domains", "registrable"]
