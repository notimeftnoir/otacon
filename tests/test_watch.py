"""Tests for watch-mode diff logic and interval parsing."""

from __future__ import annotations

import json

import pytest
from otacon.models import DomainResult, PermutationType
from otacon.theme import RiskLevel
from otacon.watch import compute_diff, parse_interval

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _result(
    domain: str,
    resolves: bool = True,
    risk_score: int = 28,
    risk_level: RiskLevel = RiskLevel.LOW,
) -> DomainResult:
    return DomainResult(
        domain=domain,
        kind=PermutationType.TYPO,
        resolves=resolves,
        risk_score=risk_score,
        risk_level=risk_level,
    )


# ---------------------------------------------------------------------------
# compute_diff — classification
# ---------------------------------------------------------------------------

def test_diff_none_baseline_all_registered_are_new() -> None:
    diff = compute_diff("google.com", [_result("googel.com")], baseline=None)
    assert len(diff.new_domains) == 1
    assert diff.new_domains[0].domain == "googel.com"
    assert diff.changed_domains == []
    assert diff.gone_domains == []


def test_diff_empty_baseline_all_registered_are_new() -> None:
    diff = compute_diff("google.com", [_result("googel.com")], baseline={})
    assert len(diff.new_domains) == 1


def test_diff_same_results_no_changes() -> None:
    baseline = {"googel.com": {"risk_score": 28, "risk_level": "low"}}
    diff = compute_diff("google.com", [_result("googel.com")], baseline=baseline)
    assert diff.new_domains == []
    assert diff.changed_domains == []
    assert diff.gone_domains == []
    assert not diff.has_changes


def test_diff_new_domain_detected() -> None:
    diff = compute_diff("google.com", [_result("googel.com")], baseline={})
    assert diff.new_domains[0].domain == "googel.com"
    assert diff.has_changes


def test_diff_gone_domain_detected() -> None:
    baseline = {
        "googel.com": {"risk_score": 28, "risk_level": "low"},
        "gooogle.com": {"risk_score": 55, "risk_level": "medium"},
    }
    diff = compute_diff("google.com", [_result("googel.com")], baseline=baseline)
    assert "gooogle.com" in diff.gone_domains
    assert diff.new_domains == []


def test_diff_changed_score_detected() -> None:
    baseline = {"googel.com": {"risk_score": 28, "risk_level": "low"}}
    diff = compute_diff(
        "google.com",
        [_result("googel.com", risk_score=53, risk_level=RiskLevel.MEDIUM)],
        baseline=baseline,
    )
    assert len(diff.changed_domains) == 1
    change = diff.changed_domains[0]
    assert change.domain == "googel.com"
    assert change.old_score == 28
    assert change.old_level == RiskLevel.LOW
    assert change.new_result.risk_score == 53
    assert change.new_result.risk_level == RiskLevel.MEDIUM


def test_diff_changed_level_only_detected() -> None:
    """Level change with same score (shouldn't happen in practice but spec says level OR score)."""
    baseline = {"googel.com": {"risk_score": 28, "risk_level": "medium"}}
    diff = compute_diff(
        "google.com",
        [_result("googel.com", risk_score=28, risk_level=RiskLevel.LOW)],
        baseline=baseline,
    )
    assert len(diff.changed_domains) == 1


def test_diff_unregistered_domain_not_classified_as_new() -> None:
    diff = compute_diff("google.com", [_result("googel.com", resolves=False)], baseline=None)
    assert diff.new_domains == []


def test_diff_has_changes_false_when_empty() -> None:
    diff = compute_diff("google.com", [], baseline={})
    assert not diff.has_changes


def test_diff_preserves_target() -> None:
    diff = compute_diff("mycompany.io", [], baseline={})
    assert diff.target == "mycompany.io"


# ---------------------------------------------------------------------------
# WatchDiff — serialization
# ---------------------------------------------------------------------------

def test_diff_json_serializable() -> None:
    diff = compute_diff("google.com", [_result("googel.com")], baseline=None)
    parsed = json.loads(diff.model_dump_json(indent=2))
    assert "new_domains" in parsed
    assert "changed_domains" in parsed
    assert "gone_domains" in parsed
    assert "target" in parsed
    assert "checked_at" in parsed


def test_diff_changed_domain_serializable() -> None:
    baseline = {"googel.com": {"risk_score": 28, "risk_level": "low"}}
    diff = compute_diff(
        "google.com",
        [_result("googel.com", risk_score=70, risk_level=RiskLevel.HIGH)],
        baseline=baseline,
    )
    parsed = json.loads(diff.model_dump_json())
    assert parsed["changed_domains"][0]["old_score"] == 28
    assert parsed["changed_domains"][0]["new_result"]["risk_score"] == 70


# ---------------------------------------------------------------------------
# parse_interval
# ---------------------------------------------------------------------------

def test_parse_interval_hours() -> None:
    assert parse_interval("24h") == 86400


def test_parse_interval_minutes() -> None:
    assert parse_interval("30m") == 1800


def test_parse_interval_seconds() -> None:
    assert parse_interval("60s") == 60


def test_parse_interval_one_hour() -> None:
    assert parse_interval("1h") == 3600


def test_parse_interval_whitespace_stripped() -> None:
    assert parse_interval("  12h  ") == 43200


def test_parse_interval_invalid_raises_value_error() -> None:
    with pytest.raises(ValueError):
        parse_interval("invalid")


def test_parse_interval_no_suffix_raises_value_error() -> None:
    with pytest.raises(ValueError):
        parse_interval("100")


def test_parse_interval_wrong_suffix_raises_value_error() -> None:
    with pytest.raises(ValueError):
        parse_interval("10d")
