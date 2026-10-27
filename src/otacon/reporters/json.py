"""JSON serialization and aggregate export formatting."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ..core.models import ScanReport
from ..core.types import RiskLevel


def to_json(report: ScanReport) -> str:
    """Serializes the full ScanReport to formatted JSON."""
    return report.model_dump_json(indent=2)


def aggregate_json(reports: dict[str, ScanReport]) -> str:
    """Serializes multiple scan reports into an aggregate JSON object with summary statistics."""
    payload = {
        "scanned_at": datetime.now(UTC).isoformat(),
        "domains": {
            domain: json.loads(report.model_dump_json()) for domain, report in reports.items()
        },
        "summary": {
            "total_registered": sum(len(r.registered) for r in reports.values()),
            "critical": sum(
                1
                for r in reports.values()
                for result in r.registered
                if result.risk_level == RiskLevel.CRITICAL
            ),
            "high": sum(
                1
                for r in reports.values()
                for result in r.registered
                if result.risk_level == RiskLevel.HIGH
            ),
            "medium": sum(
                1
                for r in reports.values()
                for result in r.registered
                if result.risk_level == RiskLevel.MEDIUM
            ),
            "low": sum(
                1
                for r in reports.values()
                for result in r.registered
                if result.risk_level == RiskLevel.LOW
            ),
        },
    }
    return json.dumps(payload, indent=2)


__all__ = ["aggregate_json", "to_json"]
