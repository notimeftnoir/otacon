"""Tests for CLI helper logic."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer

from otacon import cli


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
