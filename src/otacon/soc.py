"""Exports for security teams: STIX 2.1, MISP, and syslog for a SIEM (Wazuh).

Each format is the one its consumer imports natively, built from the scan
report with the stdlib only. Identifiers are derived from the domain
(UUIDv5), so exporting the same lookalike twice updates one object in a
threat-intel platform instead of creating duplicates.
"""

from __future__ import annotations

import json
import socket
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .models import DomainResult, ScanReport
from .theme import RiskLevel

# Stable namespace for Otacon's STIX/MISP identifiers (uuid5 of this string).
_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/notimeftnoir/otacon")
_IDENTITY = f"identity--{uuid.uuid5(_NAMESPACE, 'otacon')}"
# Only variants at or above this level are exported as indicators: a "low"
# lookalike is context, not something to block.
EXPORT_MIN = RiskLevel.MEDIUM
_MISP_THREAT_LEVEL = {"critical": 1, "high": 1, "medium": 2, "low": 3, "safe": 4}


def _ts(dt: datetime | None = None) -> str:
    return (dt or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _exportable(report: ScanReport) -> list[DomainResult]:
    return [r for r in report.registered if r.risk_level.rank >= EXPORT_MIN.rank]


def _signals(r: DomainResult) -> list[str]:
    on = [("dns", r.resolves), ("mx", r.has_mx), ("ssl", r.has_ssl), ("spf", r.has_spf)]
    out = [name for name, flag in on if flag]
    if r.http_status is not None:
        out.append(f"http {r.http_status}")
    return out


def _description(r: DomainResult, target: str) -> str:
    reasons = "; ".join(r.risk_reasons) or "registered lookalike"
    return f"Lookalike of {target} ({r.kind.value}), risk {r.risk_score}/100: {reasons}"


def _stix_quote(value: str) -> str:
    """Escapes a string literal for a STIX pattern (backslash and single quote)."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def to_stix(reports: list[ScanReport]) -> str:
    """STIX 2.1 bundle: one indicator per exportable variant and discovered host."""
    created = _ts(min((r.started_at for r in reports), default=None))
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": _IDENTITY,
            "created": created,
            "modified": created,
            "name": f"Otacon {__version__}",
            "identity_class": "system",
        }
    ]

    seen: set[str] = set()

    def indicator(
        target: str, domain: str, description: str, confidence: int, kinds: list[str]
    ) -> None:
        if domain in seen:  # the same host can come up for two targets
            return
        seen.add(domain)
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(_NAMESPACE, domain)}",
                "created_by_ref": _IDENTITY,
                "created": created,
                "modified": created,
                "name": domain,
                "description": description,
                "indicator_types": kinds,
                "pattern": f"[domain-name:value = '{_stix_quote(domain)}']",
                "pattern_type": "stix",
                "valid_from": created,
                "confidence": confidence,
                "labels": ["otacon", "domain-impersonation", target],
            }
        )

    for report in reports:
        for r in _exportable(report):
            kinds = ["malicious-activity"] if r.intel_sources else ["anomalous-activity"]
            indicator(report.target, r.domain, _description(r, report.target), r.risk_score, kinds)
        for d in report.discovered:
            reported = any(s != "CT" for s in d.sources)
            indicator(
                report.target,
                d.host,
                f"Host carrying the {report.target} brand, seen in {', '.join(d.sources)}",
                80 if reported else 40,
                ["malicious-activity"] if reported else ["anomalous-activity"],
            )
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    return json.dumps(bundle, indent=2)


def to_misp(reports: list[ScanReport]) -> str:
    """MISP event (``Import from > MISP JSON``) with one attribute per domain."""
    exportable = [(rep.target, r) for rep in reports for r in _exportable(rep)]
    worst = max(
        (r.risk_level.value for _, r in exportable),
        key=lambda v: RiskLevel(v).rank,
        default="low",
    )
    attributes: dict[str, dict[str, Any]] = {}
    for target, r in exportable:
        attributes.setdefault(
            r.domain,
            {
                "uuid": str(uuid.uuid5(_NAMESPACE, r.domain)),
                "type": "domain",
                "category": "Network activity",
                "value": r.domain,
                "to_ids": r.risk_level.rank >= RiskLevel.HIGH.rank,
                "comment": _description(r, target)[:1000],
            },
        )
    for rep in reports:
        for d in rep.discovered:
            attributes.setdefault(
                d.host,
                {
                    "uuid": str(uuid.uuid5(_NAMESPACE, d.host)),
                    "type": "domain",
                    "category": "Network activity",
                    "value": d.host,
                    "to_ids": any(s != "CT" for s in d.sources),
                    "comment": f"Carries the {rep.target} brand; seen in {', '.join(d.sources)}",
                },
            )
    targets = ", ".join(rep.target for rep in reports)
    first = min((rep.started_at for rep in reports), default=datetime.now(UTC))
    event = {
        "Event": {
            "uuid": str(uuid.uuid4()),
            "info": f"Otacon: lookalike domains of {targets}",
            "date": first.strftime("%Y-%m-%d"),
            "threat_level_id": str(_MISP_THREAT_LEVEL[worst]),
            "analysis": "1",  # ongoing
            "distribution": "0",  # your organisation only, until a human decides
            "Tag": [{"name": "tlp:amber"}, {"name": "otacon"}],
            "Attribute": list(attributes.values()),
        }
    }
    return json.dumps(event, indent=2)


def _syslog_line(body: dict[str, Any], critical: bool) -> str:
    """``<PRI>Mmm dd hh:mm:ss host otacon: {json}`` (RFC 3164).

    Wazuh's predecoder takes ``otacon`` as program_name and hands the JSON to
    its JSON decoder, so rules can match on ``otacon.risk_level`` and friends.
    """
    now = datetime.now()
    stamp = f"{now:%b} {now.day:>2} {now:%H:%M:%S}"  # RFC 3164 pads the day with a space
    host = socket.gethostname().split(".")[0] or "otacon"
    pri = 8 + (2 if critical else 4)  # facility user (1); severity critical (2) or warning (4)
    return f"<{pri}>{stamp} {host} otacon: {json.dumps({'otacon': body}, separators=(',', ':'))}"


def syslog_lines(report: ScanReport) -> list[str]:
    """One syslog line per exportable variant of *report*."""
    return [
        _syslog_line(
            {
                "event": "lookalike",
                "target": report.target,
                "domain": r.domain,
                "technique": r.kind.value,
                "risk_score": r.risk_score,
                "risk_level": r.risk_level.value,
                "signals": _signals(r),
                "intel": r.intel_sources,
                "ip": r.ip_addresses[0] if r.ip_addresses else None,
                "asn": r.asn,
            },
            critical=r.risk_level == RiskLevel.CRITICAL,
        )
        for r in _exportable(report)
    ]


def watch_lines(target: str, events: list[Any]) -> list[str]:
    """One syslog line per ``otacon watch`` event (see watch.Event)."""
    return [
        _syslog_line(
            {
                "event": f"watch.{e.kind}",
                "target": target,
                "domain": e.domain,
                "detail": e.detail,
                "risk_level": e.level,
            },
            critical=e.kind == "new" and e.level in ("critical", "high"),
        )
        for e in events
    ]


def send_syslog(lines: list[str], destination: str) -> int:
    """Sends *lines* to ``udp://host:port`` (default) or ``tcp://host:port``.

    Returns how many were sent. TCP frames each line with a newline, which is
    what Wazuh's remote syslog listener expects.
    """
    url = urlsplit(destination if "://" in destination else f"udp://{destination}")
    if url.scheme not in ("udp", "tcp") or not url.hostname:
        raise ValueError(
            f"syslog destination must be udp://host:port or tcp://host:port: {destination}"
        )
    port = url.port or 514
    family = socket.AF_INET6 if ":" in url.hostname else socket.AF_INET
    if url.scheme == "udp":
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            for line in lines:
                sock.sendto(line.encode("utf-8"), (url.hostname, port))
    else:
        with socket.create_connection((url.hostname, port), timeout=10) as sock:
            sock.sendall("".join(line + "\n" for line in lines).encode("utf-8"))
    return len(lines)
