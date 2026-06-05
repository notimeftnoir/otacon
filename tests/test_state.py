"""Tests for the watch-mode baseline persistence (state.py)."""

from __future__ import annotations

from pathlib import Path

from otacon.models import DomainResult, PermutationType
from otacon.state import baseline_path, load_baseline, save_baseline
from otacon.theme import RiskLevel

# ---------------------------------------------------------------------------
# baseline_path — pure path logic
# ---------------------------------------------------------------------------

def test_baseline_path_structure(tmp_path: Path) -> None:
    path = baseline_path("example.com", home=tmp_path)
    assert path == tmp_path / ".otacon" / "example.com.json"


def test_baseline_path_uses_home_by_default() -> None:
    path = baseline_path("example.com")
    assert path == Path.home() / ".otacon" / "example.com.json"


# ---------------------------------------------------------------------------
# load_baseline
# ---------------------------------------------------------------------------

def test_load_baseline_missing_file_returns_none(tmp_path: Path) -> None:
    assert load_baseline("example.com", home=tmp_path) is None


def test_load_baseline_corrupt_file_returns_none(tmp_path: Path) -> None:
    (tmp_path / ".otacon").mkdir()
    (tmp_path / ".otacon" / "example.com.json").write_text("not json")
    assert load_baseline("example.com", home=tmp_path) is None


def test_load_baseline_missing_registered_key_returns_none(tmp_path: Path) -> None:
    (tmp_path / ".otacon").mkdir()
    (tmp_path / ".otacon" / "example.com.json").write_text('{"target": "example.com"}')
    assert load_baseline("example.com", home=tmp_path) is None


# ---------------------------------------------------------------------------
# save_baseline + round-trip
# ---------------------------------------------------------------------------

def _registered(domain: str, score: int = 28, level: RiskLevel = RiskLevel.LOW) -> DomainResult:
    return DomainResult(
        domain=domain,
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=score,
        risk_level=level,
    )


def _unregistered(domain: str) -> DomainResult:
    return DomainResult(domain=domain, kind=PermutationType.TYPO)


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    save_baseline("google.com", [_registered("googel.com", score=28)], home=tmp_path)
    loaded = load_baseline("google.com", home=tmp_path)
    assert loaded is not None
    assert "googel.com" in loaded
    assert loaded["googel.com"]["risk_score"] == 28
    assert loaded["googel.com"]["risk_level"] == "low"


def test_save_baseline_only_stores_registered(tmp_path: Path) -> None:
    save_baseline(
        "google.com",
        [_registered("googel.com"), _unregistered("gooogle.com")],
        home=tmp_path,
    )
    loaded = load_baseline("google.com", home=tmp_path)
    assert "googel.com" in loaded
    assert "gooogle.com" not in loaded


def test_save_baseline_creates_parent_dir(tmp_path: Path) -> None:
    save_baseline("google.com", [_registered("googel.com")], home=tmp_path)
    assert (tmp_path / ".otacon").is_dir()
    assert (tmp_path / ".otacon" / "google.com.json").exists()


def test_save_baseline_overwrites_previous(tmp_path: Path) -> None:
    save_baseline("target.com", [_registered("a.com")], home=tmp_path)
    save_baseline("target.com", [_registered("b.com")], home=tmp_path)
    loaded = load_baseline("target.com", home=tmp_path)
    assert "a.com" not in loaded
    assert "b.com" in loaded


def test_save_baseline_empty_results(tmp_path: Path) -> None:
    save_baseline("target.com", [], home=tmp_path)
    loaded = load_baseline("target.com", home=tmp_path)
    assert loaded == {}
