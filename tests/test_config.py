"""Tests for what Otacon remembers between runs.

Scan history records what was found; this records what the operator decided.
The stance is the same as history's: a hand-edited or unreadable file must
cost somebody a preference, never a scan.

conftest's autouse fixture points OTACON_HOME at a temporary directory, so
nothing here touches a real one.
"""

from __future__ import annotations

import json
import stat
import sys

import pytest

from otacon import config


def test_defaults_when_nothing_has_been_stored() -> None:
    assert config.settings() == config.Settings()
    assert config.target("example.com") == config.TargetConfig()
    assert config.watched() == []


def test_settings_survive_a_round_trip() -> None:
    config.save_settings(config.Settings(theme="vision", ascii=True, fail_on="high"))
    stored = config.settings()
    assert stored.theme == "vision"
    assert stored.ascii is True
    assert stored.fail_on == "high"


def test_a_hand_edited_file_falls_back_rather_than_raising() -> None:
    """Configuration is a convenience, and one that can refuse to start is not."""
    path = config.config_dir() / "settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ this is not json", encoding="utf-8")
    assert config.settings() == config.Settings()


def test_a_wrongly_typed_value_falls_back_to_its_default() -> None:
    path = config.config_dir() / "settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"theme": 7, "fail_on": []}), encoding="utf-8")
    stored = config.settings()
    assert stored.theme == config.Settings().theme
    assert stored.fail_on is None


def test_allowing_a_domain_keeps_it_across_calls() -> None:
    """The point of the allow-list: a domain waved through because it is yours
    should stay waved through next week."""
    config.allow("example.com", "shop.example.com", "mail.example.com")
    assert config.target("example.com").allowed == ["mail.example.com", "shop.example.com"]


def test_allowing_is_idempotent_and_normalised() -> None:
    config.allow("example.com", "Shop.Example.COM")
    config.allow("example.com", "shop.example.com")
    assert config.target("example.com").allowed == ["shop.example.com"]


def test_unallowing_removes_only_what_was_named() -> None:
    config.allow("example.com", "a.example.com", "b.example.com")
    config.unallow("example.com", "a.example.com")
    assert config.target("example.com").allowed == ["b.example.com"]


def test_the_allow_list_is_per_target() -> None:
    config.allow("example.com", "shop.example.com")
    assert config.target("other.com").allowed == []


def test_watchlist_lists_only_what_is_watched() -> None:
    config.set_watched("example.com", True)
    config.set_watched("other.com", True)
    config.set_watched("other.com", False)
    assert config.watched() == ["example.com"]


def test_watching_does_not_disturb_the_allow_list() -> None:
    config.allow("example.com", "shop.example.com")
    config.set_watched("example.com", True)
    stored = config.target("example.com")
    assert stored.watched is True
    assert stored.allowed == ["shop.example.com"]


@pytest.mark.parametrize(
    "hostile",
    ["../escape", "..", "a/../../b", "", "not a domain", "/etc/passwd"],
)
def test_a_target_cannot_climb_out_of_the_config_directory(hostile: str) -> None:
    """The target comes from a scanned report, so it is attacker-influenced in
    the same way a result filename is."""
    assert config.save_target(hostile, config.TargetConfig(allowed=["x.com"])) is None
    assert config.target(hostile) == config.TargetConfig()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_stored_files_are_owner_only() -> None:
    """A watchlist says which brands somebody monitors and an allow-list says
    which lookalikes they ignore. Neither belongs to a shared host."""
    path = config.save_settings(config.Settings())
    assert path is not None
    assert stat.S_IMODE(path.stat().st_mode) == stat.S_IRUSR | stat.S_IWUSR
    assert stat.S_IMODE(path.parent.stat().st_mode) == stat.S_IRWXU


def test_opting_out_stores_nothing_and_reads_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    config.allow("example.com", "shop.example.com")
    monkeypatch.setenv("OTACON_NO_CONFIG", "1")
    assert config.save_settings(config.Settings(theme="vision")) is None
    assert config.settings() == config.Settings()
    assert config.target("example.com") == config.TargetConfig()
    assert config.watched() == []
