"""Who is behind a lookalike, and who a takedown request should go to.

RDAP (the JSON successor to WHOIS) names the registrar of a domain and the
network that owns an IP, each with an abuse contact. Those two addresses are
where a takedown actually lands, so the notice can be addressed instead of
leaving the user to dig for them.

RDAP also settles what DNS cannot: a domain whose nameservers are dead never
answers DNS, but the registry still knows it is registered.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from .resolver import _strip_unsafe_chars

_log = logging.getLogger("otacon.enrich")

_RDAP = "https://rdap.org"
_HEADERS = {"Accept": "application/rdap+json, application/json"}
_TIMEOUT = 10.0
_RETRIES = 2
_BACKOFF = 1.5
_MAX_WAIT = 10.0  # cap on a server-requested Retry-After


def _vcard(entity: dict[str, Any], field: str) -> str | None:
    """First non-empty *field* (``email``, ``fn``) of an RDAP entity's jCard."""
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) == 2 and isinstance(card[1], list)):
        return None
    for prop in card[1]:
        if isinstance(prop, list) and len(prop) == 4 and prop[0] == field and prop[3]:
            # Registry data, but printed and saved verbatim: no control characters.
            return _strip_unsafe_chars(str(prop[3])).strip() or None
    return None


def _entities(obj: Any, depth: int = 4) -> list[dict[str, Any]]:
    """Every entity in an RDAP object, nested ones included, depth first.

    Real registries nest two levels deep; *depth* bounds a pathological answer.
    """
    out: list[dict[str, Any]] = []
    if depth <= 0 or not isinstance(obj, dict):
        return out
    for e in obj.get("entities") or []:
        if isinstance(e, dict):
            out.append(e)
            out.extend(_entities(e, depth - 1))
    return out


def _with_role(obj: Any, role: str) -> list[dict[str, Any]]:
    return [e for e in _entities(obj) if role in (e.get("roles") or [])]


def abuse_email(obj: Any) -> str | None:
    """The abuse contact of an RDAP domain or IP object, wherever it is nested."""
    for entity in _with_role(obj, "abuse"):
        email = _vcard(entity, "email")
        if email and "@" in email:
            return email
    return None


def registrar_name(obj: Any) -> str | None:
    for entity in _with_role(obj, "registrar"):
        name = _vcard(entity, "fn")
        if name:
            return name
    return None


async def _rdap(client: httpx.AsyncClient, kind: str, key: str) -> tuple[int, Any]:
    """(HTTP status, parsed body or None); status 0 when the request failed.

    Registries rate-limit hard (Verisign answers a burst of ten with 429), so
    429 and 5xx are retried, honouring a numeric Retry-After.
    """
    for attempt in range(_RETRIES + 1):
        try:
            resp = await client.get(
                f"{_RDAP}/{kind}/{key}", headers=_HEADERS, timeout=_TIMEOUT, follow_redirects=True
            )
        except httpx.HTTPError as exc:
            _log.debug("RDAP %s %s failed: %r", kind, key, exc)
            return 0, None
        if resp.status_code != 429 and resp.status_code < 500:
            break
        if attempt < _RETRIES:
            wait = resp.headers.get("retry-after", "")
            await asyncio.sleep(
                min(float(wait), _MAX_WAIT) if wait.isdigit() else _BACKOFF * 2**attempt
            )
    if resp.status_code != 200:
        return resp.status_code, None
    try:
        return 200, resp.json()
    except ValueError:
        return 0, None


async def is_registered(client: httpx.AsyncClient, domain: str) -> bool | None:
    """True/False from the registry, None when RDAP could not say."""
    status, _ = await _rdap(client, "domain", domain)
    return {200: True, 404: False}.get(status)


async def takedown_contacts(
    client: httpx.AsyncClient, domain: str, ip: str | None
) -> dict[str, str]:
    """Who to send a takedown to: ``registrar``, ``registrar_abuse``, ``hosting_abuse``.

    Keys are present only when RDAP knew the answer.
    """
    out: dict[str, str] = {}
    # A subdomain spoof (example.com.verify.org) is registered as its parent
    # (verify.org): climb until the registry knows the name.
    labels = domain.split(".")
    dom = None
    for i in range(len(labels) - 1):
        status, dom = await _rdap(client, "domain", ".".join(labels[i:]))
        if status not in (400, 404):  # PIR answers 400 for a non-registrable name
            break
    if dom is not None:
        if name := registrar_name(dom):
            out["registrar"] = name
        if email := abuse_email(dom):
            out["registrar_abuse"] = email
    if ip:
        _, net = await _rdap(client, "ip", ip)
        if net is not None and (email := abuse_email(net)):
            out["hosting_abuse"] = email
    return out
