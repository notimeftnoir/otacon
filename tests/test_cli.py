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
