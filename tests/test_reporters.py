"""Tests for the reporter output generation."""

from __future__ import annotations

from otacon.models import DomainResult, PermutationType, ScanReport
from otacon.reporters import to_markdown
from otacon.theme import RiskLevel


def test_to_markdown_no_threats_contains_clear_message() -> None:
    report = ScanReport(target="example.com", total_permutations=10, results=[])

    markdown = to_markdown(report)

    assert "No suspicious registered variants detected." in markdown
    assert "**Target:** `example.com`" in markdown


def test_to_markdown_includes_detected_threat() -> None:
    result = DomainResult(
        domain="login.example.com",
        kind=PermutationType.COMBO,
        note="appended bait word",
        resolves=True,
        ip_addresses=["1.2.3.4"],
        risk_score=40,
        risk_level=RiskLevel.MEDIUM,
    )
    report = ScanReport(target="example.com", total_permutations=5, results=[result])

    markdown = to_markdown(report)

    assert "| `login.example.com` | combosquat | 40 (medium) | DNS |" in markdown
