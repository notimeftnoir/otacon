"""Tests for CLI helper logic."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer
from otacon import cli
from otacon.cli import app
from typer.testing import CliRunner


def test_load_exclusions_parses_comma_separated_values() -> None:
    exclusions = cli._load_exclusions("good.com,EXAMPLE.COM", None)
    assert exclusions == {"good.com", "example.com"}


def test_load_exclusions_reads_file(tmp_path: Path) -> None:
    file_path = tmp_path / "whitelist.txt"
    file_path.write_text("# comment\ntrusted.com\n example.com \n")

    exclusions = cli._load_exclusions(None, file_path)
    assert exclusions == {"trusted.com", "example.com"}


def test_load_exclusions_raises_for_missing_file() -> None:
    with pytest.raises(typer.BadParameter, match="exclude-file not found"):
        cli._load_exclusions(None, Path("does-not-exist.txt"))


def test_bare_invocation_calls_interactive(monkeypatch) -> None:
    """Running otacon with no subcommand must call interactive.run()."""
    called = {}

    def fake_interactive_run(console):
        called["ran"] = True

    monkeypatch.setattr("otacon.interactive.run", fake_interactive_run)

    runner = CliRunner()
    runner.invoke(app, [])
    assert called.get("ran") is True


# ---------------------------------------------------------------------------
# --fail-on exit codes (Task 05)
# ---------------------------------------------------------------------------

def _make_scan_with_result(risk_score: int, risk_level):
    """Returns a fake _run_scan coroutine that yields one registered result."""
    from otacon.models import DomainResult, PermutationType, ScanReport

    async def fake_run_scan(domain, concurrency, check_http, exclude=None):
        report = ScanReport(target=domain, total_permutations=1)
        report.results.append(
            DomainResult(
                domain="googel.com",
                kind=PermutationType.TYPO,
                resolves=True,
                risk_score=risk_score,
                risk_level=risk_level,
            )
        )
        return report

    return fake_run_scan


def test_scan_no_fail_on_exits_0_even_with_critical(monkeypatch) -> None:
    from otacon.theme import RiskLevel

    monkeypatch.setattr("otacon.cli._run_scan", _make_scan_with_result(90, RiskLevel.CRITICAL))
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "google.com"])
    assert result.exit_code == 0


def test_scan_fail_on_high_exits_2_for_critical(monkeypatch) -> None:
    from otacon.theme import RiskLevel

    monkeypatch.setattr("otacon.cli._run_scan", _make_scan_with_result(90, RiskLevel.CRITICAL))
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "google.com", "--fail-on", "high"])
    assert result.exit_code == 2


def test_scan_fail_on_high_exits_0_for_medium(monkeypatch) -> None:
    from otacon.theme import RiskLevel

    monkeypatch.setattr("otacon.cli._run_scan", _make_scan_with_result(40, RiskLevel.MEDIUM))
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "google.com", "--fail-on", "high"])
    assert result.exit_code == 0


def test_scan_fail_on_critical_exits_0_for_high(monkeypatch) -> None:
    from otacon.theme import RiskLevel

    monkeypatch.setattr("otacon.cli._run_scan", _make_scan_with_result(65, RiskLevel.HIGH))
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "google.com", "--fail-on", "critical"])
    assert result.exit_code == 0


def test_scan_fail_on_critical_exits_2_for_critical(monkeypatch) -> None:
    from otacon.theme import RiskLevel

    monkeypatch.setattr("otacon.cli._run_scan", _make_scan_with_result(90, RiskLevel.CRITICAL))
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "google.com", "--fail-on", "critical"])
    assert result.exit_code == 2


def test_scan_fail_on_medium_exits_2_for_high(monkeypatch) -> None:
    from otacon.theme import RiskLevel

    monkeypatch.setattr("otacon.cli._run_scan", _make_scan_with_result(65, RiskLevel.HIGH))
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "google.com", "--fail-on", "medium"])
    assert result.exit_code == 2


def test_scan_fail_on_low_exits_2_for_low(monkeypatch) -> None:
    from otacon.theme import RiskLevel

    monkeypatch.setattr("otacon.cli._run_scan", _make_scan_with_result(28, RiskLevel.LOW))
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "google.com", "--fail-on", "low"])
    assert result.exit_code == 2


def test_scan_fail_on_low_exits_0_for_empty_scan(monkeypatch) -> None:
    from otacon.models import ScanReport

    async def fake_empty(domain, concurrency, check_http, exclude=None):
        return ScanReport(target=domain, total_permutations=10)

    monkeypatch.setattr("otacon.cli._run_scan", fake_empty)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "google.com", "--fail-on", "low"])
    assert result.exit_code == 0


def test_scan_fail_on_help_shows_valid_choices() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert "--fail-on" in result.output


def test_watch_command_is_registered() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["watch", "--help"])
    assert result.exit_code == 0
    assert "--interval" in result.output
    assert "--notify" in result.output


def test_watch_command_invalid_interval_exits_1(tmp_path, monkeypatch) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["watch", "example.com", "--interval", "bad"])
    assert result.exit_code == 1


def test_version_flag_prints_version() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "otacon" in result.output


def test_watch_command_runs_single_scan(tmp_path, monkeypatch) -> None:
    """Single-shot watch (no --interval) runs once, writes baseline, exits 0."""
    from otacon.models import ScanReport

    async def fake_run_scan(domain, concurrency, check_http, exclude=None):
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", fake_run_scan)
    monkeypatch.setenv("HOME", str(tmp_path))

    runner = CliRunner()
    result = runner.invoke(app, ["watch", "example.com"])
    assert result.exit_code == 0
