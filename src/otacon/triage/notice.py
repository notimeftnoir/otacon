"""Abuse / takedown notice text generation.

Separated from the interactive handler so both the questionary triage flow and
the TUI render the same notice from the same source, and so the text can be
asserted in tests without driving a prompt.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..core.models import DomainResult


def _defang(value: str) -> str:
    """Breaks a hostname so a mail client cannot turn it into a live link."""
    return value.replace(".", "[.]")


def build_takedown_notice(result: DomainResult, target: str) -> str:
    """Builds a registrar-ready abuse notice for *result*, impersonating *target*.

    Every hostname in the prose is defanged, so the notice can be pasted into a
    ticket or an email client without handing the next reader a clickable link
    to a live phishing page. The raw values the registrar's own tooling needs
    are gathered in one labelled block at the end instead of being sprinkled
    through the body — three of them used to sit in the running text, which
    defeated the defanging the notice had already done.
    """
    r = result
    defanged = _defang(r.domain)
    now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    ips_str = ", ".join(r.ip_addresses) if r.ip_addresses else "N/A"
    mx_str = ", ".join(_defang(mx) for mx in r.mx_records) if r.has_mx else "None detected"
    ssl_str = (
        f"Active (Issuer: {r.ssl_issuer or 'Unknown'}, Cert Age: {r.ssl_cert_age_days}d)"
        if r.has_ssl
        else "No active certificate"
    )
    http_str = (
        f'HTTP {r.http_status} (Title: "{r.page_title or "N/A"}")'
        if r.http_status is not None
        else "No HTTP response"
    )
    reasons_bullets = (
        "\n".join(f"  - {reason}" for reason in r.risk_reasons)
        if r.risk_reasons
        else "  - Suspicious domain impersonation"
    )

    return f"""SUBJECT: Urgent Abuse / Phishing Takedown Notice: {defanged}
TARGET BRAND: {_defang(target)}

DATE: {now_str}
MALICIOUS DOMAIN: {defanged}
IMPERSONATION TECHNIQUE: {r.kind.value}
RISK EVALUATION: {r.risk_score}/100 [{r.risk_level.value.upper()}]

INCIDENT EVIDENCE:
- Domain: {defanged}
- IP Address(es): {ips_str}
- Mail Server(s) (MX): {mx_str}
- SSL/TLS Certificate: {ssl_str}
- Web Service: {http_str}
- Detected Risk Factors:
{reasons_bullets}

REQUESTED ACTION:
We request immediate suspension, de-registration, or null-routing of the domain
named above to prevent unauthorized brand impersonation, fraudulent
communications, and credential theft targeting {_defang(target)} users and
customers.

-- MACHINE-READABLE VALUES (undefanged, for registrar tooling) --
domain={r.domain}
target={target}
"""


__all__ = ["build_takedown_notice"]
