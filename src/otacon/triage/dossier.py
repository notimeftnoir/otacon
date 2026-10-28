"""Structured evidence rows for a single result.

Each row is (label, fact, meaning): what was found, and what it means for
somebody deciding whether to act. The console renders them; keeping the wording
here means the explanation does not drift between surfaces.
"""

from __future__ import annotations

from ..core.models import DomainResult
from ..net.whois import format_age


def evidence(r: DomainResult) -> list[tuple[str, str, str]]:
    """Constructs (label, fact, meaning) structured evidence rows."""
    rows: list[tuple[str, str, str]] = []
    if r.resolves:
        rows.append(("Online", ", ".join(r.ip_addresses[:3]), "points to a live server"))
    if r.has_mx:
        rows.append(
            ("Mail", ", ".join(r.mx_records[:2]), "can send email that looks like it is from you")
        )
    if r.redirects_to:
        meaning = (
            "sends visitors to your own site, likely yours"
            if r.is_likely_defensive
            else "sends visitors somewhere else"
        )
        rows.append(("Redirect", r.redirects_to, meaning))
    elif r.http_status is not None:
        title = f'"{r.page_title}"' if r.page_title else f"HTTP {r.http_status}"
        meaning = "a page is up"
        if r.title_similarity is not None and r.title_similarity >= 0.8:
            meaning = "its page title copies yours"
        rows.append(("Website", title, meaning))
    if r.has_ssl:
        age = f", {r.ssl_cert_age_days} days old" if r.ssl_cert_age_days is not None else ""
        rows.append(
            ("Certificate", f"{r.ssl_issuer or 'unknown issuer'}{age}", "browsers show a padlock")
        )
    if r.age_days is not None:
        rows.append(("Registered", format_age(r.age_days) + " ago", "domain age from WHOIS/RDAP"))
    if r.has_mx:
        spoof_info = (
            f"DMARC: {r.dmarc_policy or 'none'} (spoofable)"
            if r.is_mail_spoofable
            else f"DMARC: {r.dmarc_policy or 'enforced'}"
        )
        meaning = (
            "attacker can spoof email as this domain"
            if r.is_mail_spoofable
            else "mail exchanger configured"
        )
        rows.append(("Mail Security", spoof_info, meaning))
    if r.favicon_matches_target:
        rows.append(
            ("Favicon", f"matches target (hash: {r.favicon_hash})", "cloned brand visual identity")
        )
    if r.has_login_form:
        rows.append(("Login Form", "password input detected", "credential harvesting form on site"))
    if r.dnsbl_listed:
        rows.append(
            ("Reputation", r.dnsbl_source or "Listed", "known malicious / phishing threat IOC")
        )
    if r.is_sinkhole:
        rows.append(
            ("Sinkhole", "law enforcement / security sinkhole", "threat intercepted by authorities")
        )
    elif r.is_parked:
        rows.append(("Parked", "placeholder page", "not in use yet, keep an eye on it"))
    return rows


__all__ = ["evidence"]
