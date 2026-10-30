"""CSV export formatting hardened against spreadsheet formula injection (CWE-1236)."""

from __future__ import annotations

import csv
import io
import re

from ..core.models import ScanReport

# OWASP's trigger set: = + - @ and also tab and carriage return, which some
# spreadsheet apps strip before evaluating what follows.
_FORMULA_TRIGGER_RE = re.compile(r"^[\t\r]|^\s*[=+\-@]")


def _csv_safe(value: str) -> str:
    """Neutralises spreadsheet formula injection in untrusted cell text."""
    if _FORMULA_TRIGGER_RE.match(value):
        return "'" + value
    return value


def to_csv(report: ScanReport) -> str:
    """Generates a CSV report containing all registered domains."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(
        [
            "Domain",
            "Technique",
            "Risk Level",
            "Risk Score",
            "Age Days",
            "Resolves (DNS)",
            "Has MX",
            "Has SSL",
            "HTTP Status",
            "Redirects To",
            "Page Title",
            "Likely Defensive",
            "Notes",
        ]
    )

    for r in report.registered:
        writer.writerow(
            [
                _csv_safe(r.domain),
                r.kind.value,
                r.risk_level.value,
                r.risk_score,
                r.age_days if r.age_days is not None else "",
                r.resolves,
                r.has_mx,
                r.has_ssl,
                r.http_status if r.http_status is not None else "",
                _csv_safe(r.redirects_to or ""),
                _csv_safe(r.page_title or ""),
                r.is_likely_defensive,
                _csv_safe("; ".join(r.risk_reasons)),
            ]
        )
    return out.getvalue()


__all__ = ["_FORMULA_TRIGGER_RE", "_csv_safe", "to_csv"]
