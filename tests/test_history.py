"""Tests for the on-disk scan memory."""

from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from otacon import history
from otacon.core.models import DomainResult, ScanReport
from otacon.core.types import PermutationType, RiskLevel


def _report(target: str = "example.com", when: datetime | None = None) -> ScanReport:
    return ScanReport(
        target=target,
        started_at=when or datetime(2026, 10, 28, 9, 30, tzinfo=UTC),
        total_permutations=239,
        results=[
            DomainResult(
                domain="examp1e.com",
                kind=PermutationType.HOMOGLYPH,
                resolves=True,
                ip_addresses=["1.2.3.4"],
                risk_score=95,
                risk_level=RiskLevel.CRITICAL,
            ),
            DomainResult(domain="nothere.com", kind=PermutationType.TYPO),
        ],
    )


# ── where it lives ──────────────────────────────────────────────────────


def test_otacon_home_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OTACON_HOME", str(tmp_path / "custom"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert history.history_dir() == tmp_path / "custom"


def test_xdg_is_used_when_no_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("OTACON_HOME", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert history.history_dir() == tmp_path / "xdg" / "otacon"


def test_falls_back_to_a_dotfile_in_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OTACON_HOME", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    assert history.history_dir() == Path.home() / ".otacon"


@pytest.mark.parametrize("value", ["1", "true", "yes"])
def test_history_can_be_switched_off(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("OTACON_NO_HISTORY", value)
    assert history.enabled() is False


def test_disabled_history_writes_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OTACON_NO_HISTORY", "1")
    assert history.save(_report(), root=tmp_path) is None
    assert list(tmp_path.iterdir()) == []


# ── round trip ──────────────────────────────────────────────────────────


def test_saved_report_reads_back_identically(tmp_path: Path) -> None:
    path = history.save(_report(), root=tmp_path)
    assert path is not None
    restored = history.load(path)
    assert restored.target == "example.com"
    assert len(restored.results) == 2
    assert restored.results[0].risk_level is RiskLevel.CRITICAL


def test_record_summarises_without_a_second_parse(tmp_path: Path) -> None:
    history.save(_report(), root=tmp_path)
    (record,) = history.scans("example.com", root=tmp_path)
    assert record.registered == 1
    assert record.critical == 1
    assert record.total_permutations == 239
    assert "1 registered, 1 critical" in record.label


def test_scans_are_listed_newest_first(tmp_path: Path) -> None:
    base = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
    for days in range(3):
        history.save(_report(when=base + timedelta(days=days)), root=tmp_path)
    found = history.scans("example.com", root=tmp_path)
    assert [r.started_at.day for r in found] == [22, 21, 20]


def test_latest_returns_the_newest_report(tmp_path: Path) -> None:
    base = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
    history.save(_report(when=base), root=tmp_path)
    history.save(_report(when=base + timedelta(days=5)), root=tmp_path)
    newest = history.latest("example.com", root=tmp_path)
    assert newest is not None
    assert newest.started_at.day == 25


def test_targets_lists_only_directories_holding_scans(tmp_path: Path) -> None:
    history.save(_report("example.com"), root=tmp_path)
    history.save(_report("other.org"), root=tmp_path)
    (tmp_path / "empty.net").mkdir()
    assert history.targets(root=tmp_path) == ["example.com", "other.org"]


def test_unknown_target_lists_nothing(tmp_path: Path) -> None:
    assert history.scans("never-scanned.com", root=tmp_path) == []
    assert history.latest("never-scanned.com", root=tmp_path) is None


# ── bounded growth and deletion ─────────────────────────────────────────


def test_save_prunes_to_the_keep_limit(tmp_path: Path) -> None:
    base = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
    for days in range(6):
        history.save(_report(when=base + timedelta(days=days)), root=tmp_path, keep=3)
    found = history.scans("example.com", root=tmp_path)
    assert len(found) == 3
    assert [r.started_at.day for r in found] == [6, 5, 4]


def test_forget_removes_the_target_entirely(tmp_path: Path) -> None:
    history.save(_report(), root=tmp_path)
    assert history.forget("example.com", root=tmp_path) == 1
    assert history.targets(root=tmp_path) == []


# ── containment and robustness ──────────────────────────────────────────


@pytest.mark.parametrize("hostile", ["../../etc", "..", "/etc/passwd", "a/b", ""])
def test_a_target_cannot_escape_the_history_directory(tmp_path: Path, hostile: str) -> None:
    with pytest.raises(ValueError):
        history.save(_report(hostile), root=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_a_hostile_target_lists_nothing_rather_than_raising(tmp_path: Path) -> None:
    assert history.scans("../../etc", root=tmp_path) == []


def test_a_corrupt_file_is_skipped_not_fatal(tmp_path: Path) -> None:
    history.save(_report(), root=tmp_path)
    (tmp_path / "example.com" / "99999999T000000Z.json").write_text("{ truncated", encoding="utf-8")
    found = history.scans("example.com", root=tmp_path)
    assert len(found) == 1
    assert found[0].registered == 1


@pytest.mark.skipif(
    not hasattr(stat, "S_IRWXU") or Path.home().drive != "",
    reason="POSIX permission bits",
)
def test_stored_scans_are_owner_only(tmp_path: Path) -> None:
    """A scan reveals which brand is being watched; it is not world-readable."""
    path = history.save(_report(), root=tmp_path)
    assert path is not None
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_the_suite_never_writes_to_the_real_history(isolate_scan_history: Path) -> None:
    """Guards the conftest fixture that keeps fixture domains out of ~/.otacon.

    `execute_scan` persists through `history.save`, so any test that reaches it
    writes somewhere. Before this fixture existed, that somewhere was the
    developer's own home directory, which filled with `evil-twin.com`,
    `clean.com` and `a.com`.
    """
    assert history.history_dir() == isolate_scan_history
    assert history.history_dir() != Path.home() / ".otacon"

    history.save(_report("fixture-domain.com"))
    assert history.targets() == ["fixture-domain.com"]
    assert (isolate_scan_history / "fixture-domain.com").is_dir()


def test_a_cli_scan_persists_into_the_isolated_directory(
    isolate_scan_history: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The path that leaked: the scan command saves whatever it just produced."""
    from otacon.cli.commands import scan as scan_cmd

    saved = _report("from-cli.com")
    scan_cmd.history.save(saved)
    assert (isolate_scan_history / "from-cli.com").is_dir()


def test_two_scans_in_the_same_second_are_both_kept(tmp_path) -> None:
    """The filename is a timestamp accurate to the second.

    Two runs started inside the same one used to land on the same name, and the
    second silently replaced the first — in the one place whose whole job is to
    keep every scan.
    """
    report = ScanReport(target="example.com", total_permutations=1)
    paths = [history.save(report, root=tmp_path) for _ in range(3)]

    assert len(set(paths)) == 3
    assert len(list((tmp_path / "example.com").glob("*.json"))) == 3


def test_the_suffix_does_not_break_newest_first_ordering(tmp_path) -> None:
    """scans() sorts filenames in reverse, so a suffix must not outrank a later scan."""
    from datetime import UTC, datetime

    early = ScanReport(target="example.com", started_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC))
    late = ScanReport(target="example.com", started_at=datetime(2026, 1, 2, 0, 0, 0, tzinfo=UTC))
    history.save(early, root=tmp_path)
    history.save(early, root=tmp_path)  # same second -> suffixed
    history.save(late, root=tmp_path)

    assert history.scans("example.com", root=tmp_path)[0].started_at == late.started_at


# ---------------------------------------------------------------------------
# containment: the target name comes off a scanned report
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="platform cannot create symlinks")
def test_a_symlinked_target_directory_is_refused(tmp_path) -> None:
    """The containment check is the only thing that can catch this.

    `is_valid_domain` runs first and sees nothing wrong — "example.com" is a
    perfectly ordinary domain. But if something has placed a symlink at
    <history>/example.com pointing out of the history root, resolving it lands
    the report somewhere else entirely: on a shared host that is a write
    anywhere the symlink points, which is the same threat the owner-only
    permissions here address.
    """
    root = tmp_path / "home"
    outside = tmp_path / "elsewhere"
    root.mkdir()
    outside.mkdir()
    try:
        (root / "example.com").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform does not allow creating symlinks here")

    with pytest.raises(ValueError, match="refusing to store history outside"):
        history.save(ScanReport(target="example.com"), root=root)

    assert not list(outside.iterdir()), "a report was written outside the history root"


def test_a_symlinked_target_config_is_refused(tmp_path) -> None:
    """The same guard, in the other store that takes a name off a report."""
    from otacon import config

    root = tmp_path / "home"
    outside = tmp_path / "elsewhere"
    (root / "config" / "targets").mkdir(parents=True)
    outside.mkdir()
    try:
        (root / "config" / "targets" / "example.com.json").symlink_to(outside / "stolen.json")
    except (OSError, NotImplementedError):
        pytest.skip("this platform does not allow creating symlinks here")

    # save_target swallows the refusal by design — configuration must never cost
    # somebody a scan — so assert the file, not the exception.
    config.save_target("example.com", config.TargetConfig(allowed=["x.com"]), root=root)
    assert not (outside / "stolen.json").exists(), "config was written outside its root"
