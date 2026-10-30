"""Abuse / takedown notice text generation.

Separated from the interactive handler so both the questionary triage flow and
the TUI render the same notice from the same source, and so the text can be
asserted in tests without driving a prompt.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..core.models import DomainResult


def build_takedown_notice(result: DomainResult, target: str) -> str:
    """Builds a registrar-ready abuse notice for *result*, impersonating *target*.

    The domain is defanged in the human-facing fields so the notice can be pasted
    into a ticket or email client without creating a live link, with the raw value
    kept alongside it for the registrar's own tooling.
    """
    r = result
    defanged = r.domain.replace(".", "[.]")
    now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    ips_str = ", ".join(r.ip_addresses) if r.ip_addresses else "N/A"
    mx_str = ", ".join(r.mx_records) if r.has_mx else "None detected"
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
TARGET BRAND: {target}

DATE: {now_str}
MALICIOUS DOMAIN: {defanged} (raw: {r.domain})
IMPERSONATION TECHNIQUE: {r.kind.value}
RISK EVALUATION: {r.risk_score}/100 [{r.risk_level.value.upper()}]

INCIDENT EVIDENCE:
- Domain: {r.domain}
- IP Address(es): {ips_str}
- Mail Server(s) (MX): {mx_str}
- SSL/TLS Certificate: {ssl_str}
- Web Service: {http_str}
- Detected Risk Factors:
{reasons_bullets}

REQUESTED ACTION:
We request immediate suspension, de-registration, or null-routing of domain '{r.domain}'
to prevent unauthorized brand impersonation, fraudulent communications, and credential theft
targeting {target} users and customers.
"""


__all__ = ["build_takedown_notice"]
