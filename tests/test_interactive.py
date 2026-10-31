"""Tests for the interactive mode module."""

from __future__ import annotations

import io
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC
from pathlib import Path
from typing import Any
from unittest.mock import DEFAULT, AsyncMock, MagicMock, patch

import pytest
from rich.console import Console

import otacon.triage.actions
import otacon.triage.prompts
import otacon.triage.workflow
from otacon.core.models import DomainResult, Permutation, ScanReport
from otacon.core.types import PermutationType, RiskLevel
from otacon.triage.actions import (
    _export_result,
    _rescan_result,
    _show_whois,
    _suggest_defensive_whitelist,
)
from otacon.triage.prompts import _confirm, _validate_domain, _validate_limit, _YNValidator
from otacon.triage.workflow import (
    _action_loop,
    _interactive_generate,
    _interactive_scan,
    _scan,
    run,
)

_TRIAGE_MODULES = (otacon.triage.workflow, otacon.triage.actions, otacon.triage.prompts)


@contextmanager
def _patch_triage(name: str, new: object = DEFAULT, **kwargs: object) -> Iterator[Any]:
    """Patches *name* in every triage module that looks it up, all with one object."""
    with ExitStack() as stack:
        target: Any = DEFAULT
        for mod in _TRIAGE_MODULES:
            if not hasattr(mod, name):
                continue
            if target is DEFAULT:
                target = stack.enter_context(patch.object(mod, name, new, **kwargs))
            else:
                stack.enter_context(patch.object(mod, name, target))
        assert target is not DEFAULT, f"no triage module has {name!r}"
        yield target


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------


def _registered(domain: str = "googel.com", score: int = 50) -> DomainResult:
    return DomainResult(
        domain=domain,
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=score,
        risk_level=RiskLevel.MEDIUM,
    )


def test_validate_domain_empty_string():
    assert _validate_domain("") == "Domain cannot be empty"


def test_validate_domain_whitespace_only():
    assert _validate_domain("   ") == "Domain cannot be empty"


def test_validate_domain_valid():
    assert _validate_domain("example.com") is True


def test_validate_domain_no_tld_rejected():
    assert _validate_domain("example") is not True  # bare label without TLD is invalid


def test_validate_domain_invalid_scheme_rejected():
    assert _validate_domain("http://example.com") is not True


def test_validate_domain_empty_rejected():
    assert _validate_domain("   ") is not True


def test_validate_limit_zero():
    assert _validate_limit("0") is True


def test_validate_limit_positive():
    assert _validate_limit("42") is True


def test_validate_limit_negative():
    assert _validate_limit("-1") == "Enter 0 or greater"


def test_validate_limit_not_a_number():
    assert _validate_limit("abc") == "Enter a number (0 = all)"


def test_run_exits_cleanly_on_domain_ctrl_c():
    """Ctrl+C on domain input must exit without raising."""
    with _patch_triage("questionary") as mock_q:
        mock_q.text.return_value.ask.return_value = None
        run(MagicMock())


def test_run_exits_cleanly_on_mode_ctrl_c():
    """Ctrl+C on mode selection must exit without raising."""
    with _patch_triage("questionary") as mock_q:
        mock_q.text.return_value.ask.return_value = "example.com"
        mock_q.select.return_value.ask.return_value = None
        run(MagicMock())


def test_run_routes_to_scan(monkeypatch):
    """Mode=scan must call _interactive_scan."""
    called = {}

    def fake_scan(domain, console):
        called["domain"] = domain

    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("_interactive_scan", fake_scan),
    ):
        mock_q.text.return_value.ask.return_value = "  example.com  "
        mock_q.select.return_value.ask.return_value = "scan"
        run(MagicMock())

    assert called["domain"] == "example.com"


def test_run_routes_to_generate(monkeypatch):
    """Mode=generate must call _interactive_generate."""
    called = {}

    def fake_generate(domain, console):
        called["domain"] = domain

    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("_interactive_generate", fake_generate),
    ):
        mock_q.text.return_value.ask.return_value = "example.com"
        mock_q.select.return_value.ask.return_value = "generate"
        run(MagicMock())

    assert called["domain"] == "example.com"


def test_interactive_generate_prints_variants():
    """generate branch must render variants to console."""
    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("permutations") as mock_perms,
    ):
        mock_perms.generate.return_value = [
            Permutation(domain="exmaple.com", kind=PermutationType.TYPO, note="swap"),
            Permutation(domain="examplee.com", kind=PermutationType.TYPO, note="dup"),
        ]
        mock_q.text.return_value.ask.return_value = "0"
        console = MagicMock()
        _interactive_generate("example.com", console)

    assert console.print.called


def test_interactive_generate_ctrl_c_on_limit():
    """Ctrl+C on limit input must exit without raising."""
    with _patch_triage("questionary") as mock_q:
        mock_q.text.return_value.ask.return_value = None
        console = MagicMock()
        _interactive_generate("example.com", console)
        console.print.assert_not_called()


def test_interactive_generate_respects_limit():
    """A non-zero limit must cap the printed variants."""
    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("permutations") as mock_perms,
    ):
        mock_perms.generate.return_value = [
            Permutation(domain=f"ex{i}mple.com", kind=PermutationType.TYPO, note="x")
            for i in range(10)
        ]
        mock_q.text.return_value.ask.return_value = "3"
        console = MagicMock()
        _interactive_generate("example.com", console)

    # header print + 3 variant prints + 1 "... and N more" print = 5 calls
    assert console.print.call_count == 5


def test_confirm_returns_true_for_y():
    """_confirm returns True when user types y."""
    with _patch_triage("_pt_prompt", return_value="y"):
        assert _confirm("Continue?") is True


def test_confirm_returns_false_for_n():
    """_confirm returns False when user types n."""
    with _patch_triage("_pt_prompt", return_value="n"):
        assert _confirm("Continue?") is False


def test_confirm_returns_false_for_enter():
    """_confirm defaults to False when user presses Enter (empty input)."""
    with _patch_triage("_pt_prompt", return_value=""):
        assert _confirm("Continue?") is False


def test_confirm_returns_none_on_ctrl_c():
    """_confirm returns None on KeyboardInterrupt (Ctrl+C)."""
    with _patch_triage("_pt_prompt", side_effect=KeyboardInterrupt):
        assert _confirm("Continue?") is None


def test_yn_validator_accepts_y_n_and_empty():
    """_YNValidator must not raise for any of the accepted buffer contents."""
    from prompt_toolkit.document import Document

    validator = _YNValidator()
    for text in ("y", "Y", "n", "N", "", "  "):
        validator.validate(Document(text=text))  # must not raise


def test_yn_validator_rejects_anything_else():
    from prompt_toolkit.document import Document
    from prompt_toolkit.validation import ValidationError

    validator = _YNValidator()
    with pytest.raises(ValidationError):
        validator.validate(Document(text="maybe"))


def test_confirm_yes_keybinding_auto_submits():
    """Real prompt_toolkit session: typing 'y' fires the auto-submit binding
    (_yes) without needing Enter."""
    from prompt_toolkit.application import create_app_session
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    with create_pipe_input() as pipe_input:
        pipe_input.send_text("y")
        with create_app_session(input=pipe_input, output=DummyOutput()):
            assert _confirm("Continue?") is True


def test_confirm_no_keybinding_auto_submits():
    """Real prompt_toolkit session: typing 'n' fires the auto-submit binding
    (_no) without needing Enter."""
    from prompt_toolkit.application import create_app_session
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    with create_pipe_input() as pipe_input:
        pipe_input.send_text("n")
        with create_app_session(input=pipe_input, output=DummyOutput()):
            assert _confirm("Continue?") is False


def test_interactive_scan_full_calls_render_table(monkeypatch, tmp_path):
    """Full scan (HTTP) must call reporters.render_table with correct params."""
    monkeypatch.chdir(tmp_path)
    mock_report = ScanReport(target="example.com", total_permutations=0)

    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("_confirm", return_value=False),
        _patch_triage("_scan", new_callable=AsyncMock) as mock_scan,
        _patch_triage("reporters") as mock_reporters,
    ):
        mock_q.select.return_value.ask.return_value = "full"
        mock_scan.return_value = mock_report
        console = MagicMock()
        _interactive_scan("example.com", console)

    mock_scan.assert_called_once_with(
        "example.com", concurrency=50, check_http=True, console=console, exclude=None
    )
    mock_reporters.render_table.assert_called_once_with(mock_report, console, show_safe=False)


def test_interactive_scan_dns_only(monkeypatch, tmp_path):
    """DNS-only scan must pass check_http=False."""
    monkeypatch.chdir(tmp_path)
    mock_report = ScanReport(target="example.com", total_permutations=0)

    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("_confirm", return_value=False),
        _patch_triage("_scan", new_callable=AsyncMock) as mock_scan,
        _patch_triage("reporters"),
    ):
        mock_q.select.return_value.ask.return_value = "dns"
        mock_scan.return_value = mock_report
        _interactive_scan("example.com", MagicMock())

    mock_scan.assert_called_once_with(
        "example.com",
        concurrency=50,
        check_http=False,
        console=mock_scan.call_args[1]["console"],
        exclude=None,
    )


def test_interactive_scan_reads_whitelist_file(monkeypatch, tmp_path):
    """A whitelist.txt in the cwd is parsed (comments/blanks skipped) and
    passed through as the exclude set."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "whitelist.txt").write_text(
        "# defensive registrations\ngooogle.com\n\ngoogle-inc.com\n", encoding="utf-8"
    )
    mock_report = ScanReport(target="example.com", total_permutations=0)

    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("_confirm", return_value=False),
        _patch_triage("_scan", new_callable=AsyncMock) as mock_scan,
        _patch_triage("reporters"),
    ):
        mock_q.select.return_value.ask.return_value = "full"
        mock_scan.return_value = mock_report
        _interactive_scan("example.com", MagicMock())

    assert mock_scan.call_args[1]["exclude"] == {"gooogle.com", "google-inc.com"}


def test_interactive_scan_ignores_unreadable_whitelist_file(monkeypatch, tmp_path):
    """An unreadable whitelist.txt must degrade gracefully instead of crashing
    the interactive scan."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "whitelist.txt").write_text("gooogle.com\n", encoding="utf-8")
    mock_report = ScanReport(target="example.com", total_permutations=0)

    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("_confirm", return_value=False),
        _patch_triage("_scan", new_callable=AsyncMock) as mock_scan,
        _patch_triage("reporters"),
        patch.object(Path, "read_text", side_effect=OSError("permission denied")),
    ):
        mock_q.select.return_value.ask.return_value = "full"
        mock_scan.return_value = mock_report
        _interactive_scan("example.com", MagicMock())

    assert mock_scan.call_args[1]["exclude"] is None


def test_interactive_scan_ctrl_c_on_network():
    """Ctrl+C on network selection must exit without raising."""
    with _patch_triage("questionary") as mock_q:
        mock_q.select.return_value.ask.return_value = None
        _interactive_scan("example.com", MagicMock())


def test_interactive_scan_ctrl_c_on_show_all():
    """Ctrl+C on show-all must exit without raising."""
    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("_confirm", return_value=None),
        _patch_triage("_scan", new_callable=AsyncMock),
    ):
        mock_q.select.return_value.ask.return_value = "full"
        _interactive_scan("example.com", MagicMock())


# ---------------------------------------------------------------------------
# Action loop (Task 06)
# ---------------------------------------------------------------------------


def test_action_loop_skips_when_no_registered():
    """Empty report → no prompt shown."""
    with _patch_triage("questionary") as mock_q:
        report = ScanReport(target="example.com", total_permutations=5)
        _action_loop(report, "example.com", MagicMock(), check_http=True)
        mock_q.select.assert_not_called()


def test_action_loop_ctrl_c_on_domain_picker():
    """Ctrl+C on domain picker exits cleanly."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with _patch_triage("questionary") as mock_q:
        mock_q.select.return_value.ask.return_value = None
        _action_loop(report, "example.com", MagicMock(), check_http=True)


def test_action_loop_quit_choice_returns_title_string():
    """Selecting '── quit ──' returns its title (not None) in questionary 2.x; must exit cleanly."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with _patch_triage("questionary") as mock_q:
        mock_q.select.return_value.ask.return_value = "── quit ──"
        _action_loop(report, "example.com", MagicMock(), check_http=True)


def test_action_loop_quit_from_action_menu():
    """Quit from action menu exits loop."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with _patch_triage("questionary") as mock_q:
        mock_q.select.return_value.ask.side_effect = [r, "quit"]
        _action_loop(report, "example.com", MagicMock(), check_http=True)


def test_action_loop_ctrl_c_from_action_menu():
    """None from action menu exits loop."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with _patch_triage("questionary") as mock_q:
        mock_q.select.return_value.ask.side_effect = [r, None]
        _action_loop(report, "example.com", MagicMock(), check_http=True)


def test_action_loop_back_returns_to_domain_picker():
    """Back action returns to domain picker (outer loop)."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with _patch_triage("questionary") as mock_q:
        # back → domain picker again → None (Ctrl+C)
        mock_q.select.return_value.ask.side_effect = [r, "back", None]
        _action_loop(report, "example.com", MagicMock(), check_http=True)
        assert mock_q.select.return_value.ask.call_count == 3


def test_action_loop_open_calls_webbrowser():
    """Open action shows a warning, asks for confirmation, then calls webbrowser.open."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("webbrowser") as mock_wb,
        _patch_triage("_confirm", return_value=True),
    ):
        mock_q.select.return_value.ask.side_effect = [r, "open", "quit"]
        _action_loop(report, "example.com", MagicMock(), check_http=True)
    mock_wb.open.assert_called_once_with("https://googel.com")


def test_action_loop_open_cancelled_when_user_declines():
    """Declining the warning prompt cancels the browser open."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("webbrowser") as mock_wb,
        _patch_triage("_confirm", return_value=False),
    ):
        mock_q.select.return_value.ask.side_effect = [r, "open", "quit"]
        _action_loop(report, "example.com", MagicMock(), check_http=True)
    mock_wb.open.assert_not_called()


def test_action_loop_whois_calls_show_whois():
    """Whois action calls _show_whois with the selected result."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("_show_whois") as mock_show,
    ):
        mock_q.select.return_value.ask.side_effect = [r, "whois", "quit"]
        _action_loop(report, "example.com", MagicMock(), check_http=True)
    mock_show.assert_called_once_with(r, mock_show.call_args[0][1])


def test_action_loop_export_calls_export_result():
    """Export action calls _export_result with the selected result."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("_export_result") as mock_export,
    ):
        mock_q.select.return_value.ask.side_effect = [r, "export", "quit"]
        _action_loop(report, "example.com", MagicMock(), check_http=True)
    assert mock_export.called


def test_action_loop_takedown_generates_report(tmp_path, monkeypatch):
    """Takedown action formats an abuse report and can save it to disk."""
    monkeypatch.chdir(tmp_path)
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with _patch_triage("questionary") as mock_q:
        # 1. select domain `r`
        # 2. select action `takedown`
        # 3. select takedown option `save`
        # 4. filename text prompt
        # 5. next action loop: `quit`
        mock_q.select.return_value.ask.side_effect = [r, "takedown", "save", "quit"]
        mock_q.text.return_value.ask.return_value = "takedown.txt"
        _action_loop(report, "example.com", MagicMock(), check_http=True)
    out_file = tmp_path / "takedown.txt"
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "PHISHING TAKEDOWN NOTICE" in content.upper()
    assert "googel[.]com" in content


def test_action_loop_takedown_treats_page_title_as_literal_text():
    """A hostile <title> such as ``[/]`` must not crash the notice or turn
    into Rich markup (e.g. a clickable ``[link=…]``) in the user's terminal."""
    from rich.console import Console

    from otacon.utils.theme import OTACON_THEME

    r = _registered()
    r.http_status = 200
    r.page_title = "[/][link=https://evil.example]Login[/link]"
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    console = Console(record=True, width=200, theme=OTACON_THEME)
    with _patch_triage("questionary") as mock_q:
        mock_q.select.return_value.ask.side_effect = [r, "takedown", "back", "quit"]
        _action_loop(report, "example.com", console, check_http=True)
    assert "[/][link=https://evil.example]Login[/link]" in console.export_text()


def test_action_loop_allow_removes_domain_from_next_iteration():
    """Allow adds domain to session whitelist → domain absent from next outer loop."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with _patch_triage("questionary") as mock_q:
        # allow → outer loop: no candidates → exits
        mock_q.select.return_value.ask.side_effect = [r, "allow"]
        _action_loop(report, "example.com", MagicMock(), check_http=True)
    # domain picker + action picker = 2 calls; no third call (no candidates remain)
    assert mock_q.select.return_value.ask.call_count == 2


def test_action_loop_rescan_updates_report_and_selected():
    """Rescan action calls _rescan_result and updates the report in-place."""
    r = _registered(score=50)
    updated = _registered(score=75)
    updated = updated.model_copy(update={"risk_level": RiskLevel.HIGH})
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("_rescan_result", return_value=updated) as mock_rescan,
        _patch_triage("reporters"),
    ):
        mock_q.select.return_value.ask.side_effect = [r, "rescan", "quit"]
        _action_loop(report, "example.com", MagicMock(), check_http=False)
    assert mock_rescan.called
    assert report.results[0].risk_score == 75


def test_action_loop_rescan_finds_match_past_first_entry():
    """The rescan handler's report-patching loop must keep scanning past a
    non-matching entry instead of only ever checking index 0."""
    other = _registered(score=10)
    other = other.model_copy(update={"domain": "unrelated.com"})
    r = _registered(score=50)
    updated = r.model_copy(update={"risk_score": 75, "risk_level": RiskLevel.HIGH})
    report = ScanReport(target="example.com", total_permutations=5, results=[other, r])
    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("_rescan_result", return_value=updated),
        _patch_triage("reporters"),
    ):
        mock_q.select.return_value.ask.side_effect = [r, "rescan", "quit"]
        _action_loop(report, "example.com", MagicMock(), check_http=False)
    assert report.results[0].domain == "unrelated.com"
    assert report.results[1].risk_score == 75


def test_run_action_menu_ignores_unknown_action():
    """An action string outside the dispatch table (defensive fallback) must
    be skipped instead of crashing the menu loop."""
    from otacon.triage.actions import _ActionContext
    from otacon.triage.workflow import _run_action_menu

    r = _registered(score=50)
    ctx = _ActionContext(
        selected=r,
        target="example.com",
        check_http=False,
        report=ScanReport(target="example.com", total_permutations=1, results=[r]),
        session_allowed=set(),
        console=MagicMock(),
    )
    with _patch_triage("questionary") as mock_q:
        mock_q.select.return_value.ask.side_effect = ["unknown-action", "quit"]
        outcome = _run_action_menu(ctx)
    assert outcome == "quit"


# ---------------------------------------------------------------------------
# _scan — real function body (Progress/Live rendering, hijack banner), network
# mocked out via a fake Resolver so nothing touches the wire.
# ---------------------------------------------------------------------------


class _FakeResolver:
    """Minimal async-context-manager stand-in for Resolver — no real network I/O."""

    dns_hijack_detected = False

    def __init__(self, concurrency, check_http, target, check_whois=True, check_dnsbl=True) -> None:
        self.target_title = None

    async def __aenter__(self) -> _FakeResolver:
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    async def check_one(self, perm):
        return DomainResult(domain=perm.domain, kind=perm.kind, resolves=True)


class _HijackResolver(_FakeResolver):
    dns_hijack_detected = True


def _two_fake_perms():
    return [
        Permutation(domain="evil1.example.com", kind=PermutationType.TYPO),
        Permutation(domain="evil2.example.com", kind=PermutationType.TYPO),
    ]


def _patch_scan_deps(monkeypatch, resolver_cls=_FakeResolver) -> None:
    monkeypatch.setattr(
        "otacon.permutations.generate",
        lambda target, exclude=None: _two_fake_perms(),
    )
    monkeypatch.setattr("otacon.engine.scanner.Resolver", resolver_cls)


@pytest.mark.asyncio
async def test_scan_returns_empty_report_when_no_permutations(monkeypatch):
    monkeypatch.setattr("otacon.permutations.generate", lambda target, exclude=None: [])
    report = await _scan("example.com", concurrency=5, check_http=True, console=MagicMock())
    assert report.results == []
    assert report.total_permutations == 0


def _buffered_console() -> Console:
    """A real Console over an in-memory buffer — Progress/Live need genuine
    timing behavior that a MagicMock can't fake."""
    return Console(file=io.StringIO(), force_terminal=False)


@pytest.mark.asyncio
async def test_scan_collects_registered_hits(monkeypatch):
    _patch_scan_deps(monkeypatch)
    report = await _scan("example.com", concurrency=5, check_http=True, console=_buffered_console())
    assert report.total_permutations == 2
    assert len(report.results) == 2
    assert all(r.is_registered for r in report.results)


@pytest.mark.asyncio
async def test_scan_reports_dns_hijack_warning(monkeypatch):
    _patch_scan_deps(monkeypatch, resolver_cls=_HijackResolver)
    console = _buffered_console()
    report = await _scan("example.com", concurrency=5, check_http=True, console=console)
    assert report.dns_hijack_detected is True
    assert "NXDOMAIN hijacking" in console.file.getvalue()


def test_action_loop_called_after_render_in_interactive_scan():
    """_interactive_scan calls _action_loop after render_table."""
    mock_report = ScanReport(target="example.com", total_permutations=0)
    called = {}

    def fake_loop(report, domain, console, check_http):
        called["ran"] = True

    with (
        _patch_triage("questionary") as mock_q,
        _patch_triage("_confirm", return_value=False),
        _patch_triage("_scan", new_callable=AsyncMock) as mock_scan,
        _patch_triage("reporters"),
        _patch_triage("_action_loop", fake_loop),
    ):
        mock_q.select.return_value.ask.return_value = "full"
        mock_scan.return_value = mock_report
        _interactive_scan("example.com", MagicMock())

    assert called.get("ran") is True


# ---------------------------------------------------------------------------
# _show_whois
# ---------------------------------------------------------------------------


def test_show_whois_uses_cached_data_without_fetch():
    """_show_whois shows cached created_at from the result — no WHOIS lookup."""
    from datetime import datetime

    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        created_at=datetime(2024, 3, 1, tzinfo=UTC),
        age_days=90,
    )
    with _patch_triage("fetch_domain_age") as mock_fetch:
        console = MagicMock()
        _show_whois(r, console)
    mock_fetch.assert_not_called()
    assert console.print.called


def test_show_whois_fetches_when_no_cache():
    """_show_whois fetches WHOIS when created_at is None."""
    from datetime import datetime

    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)

    async def _fake_fetch(domain):
        return (datetime(2024, 1, 1, tzinfo=UTC), 150)

    with _patch_triage("fetch_domain_age", _fake_fetch):
        console = MagicMock()
        _show_whois(r, console)
    assert console.print.called


def test_show_whois_shows_unavailable_on_failed_lookup():
    """_show_whois prints 'unavailable' when fetch returns (None, None)."""
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)

    async def _fake_fetch(domain):
        return (None, None)

    with _patch_triage("fetch_domain_age", _fake_fetch):
        console = MagicMock()
        _show_whois(r, console)
    printed = " ".join(str(c) for c in console.print.call_args_list)
    assert "unavailable" in printed


def test_show_whois_prints_ips_and_mx_records():
    """IPs and MX records are printed (capped at 3) when present on the result."""
    from datetime import datetime

    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        created_at=datetime(2024, 3, 1, tzinfo=UTC),
        age_days=90,
        ip_addresses=["1.2.3.4", "1.2.3.5"],
        mx_records=["mail.googel.com"],
    )
    console = MagicMock()
    _show_whois(r, console)
    printed = " ".join(str(c) for c in console.print.call_args_list)
    assert "1.2.3.4" in printed
    assert "mail.googel.com" in printed


# ---------------------------------------------------------------------------
# _export_result
# ---------------------------------------------------------------------------


def test_export_result_writes_json_to_file(tmp_path, monkeypatch):
    """_export_result saves valid JSON for a relative filename under the CWD."""
    monkeypatch.chdir(tmp_path)
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)
    with _patch_triage("questionary") as mock_q:
        mock_q.text.return_value.ask.return_value = "googel_com.json"
        _export_result(r, MagicMock())
    out_file = tmp_path / "googel_com.json"
    assert out_file.exists()
    import json

    data = json.loads(out_file.read_text())
    assert data["domain"] == "googel.com"


@pytest.mark.parametrize("bad_name", ["../escape.json", "/tmp/abs.json", "C:\\abs.json"])
def test_export_result_rejects_paths_outside_cwd(tmp_path, monkeypatch, bad_name):
    """Absolute paths and `..` escapes are refused — write stays inside the CWD."""
    monkeypatch.chdir(tmp_path)
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)
    with _patch_triage("questionary") as mock_q:
        mock_q.text.return_value.ask.return_value = bad_name
        _export_result(r, MagicMock())
    # Nothing escaped the working directory (parent stays empty of our file).
    assert not (tmp_path.parent / "escape.json").exists()
    assert list(tmp_path.rglob("*.json")) == []


def test_export_result_ctrl_c_exits_cleanly():
    """Ctrl+C on filename prompt exits without error."""
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)
    with _patch_triage("questionary") as mock_q:
        mock_q.text.return_value.ask.return_value = None
        _export_result(r, MagicMock())  # must not raise


def test_export_result_handles_write_failure(tmp_path, monkeypatch):
    """A write failure (disk full, permissions, ...) is reported, not raised."""
    monkeypatch.chdir(tmp_path)
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)
    console = MagicMock()
    with (
        _patch_triage("questionary") as mock_q,
        patch.object(Path, "write_text", side_effect=OSError("disk full")),
    ):
        mock_q.text.return_value.ask.return_value = "googel_com.json"
        _export_result(r, console)
    printed = " ".join(str(c) for c in console.print.call_args_list)
    assert "disk full" in printed


# ---------------------------------------------------------------------------
# _rescan_result
# ---------------------------------------------------------------------------


def test_rescan_result_returns_scored_domain_result():
    """_rescan_result returns a DomainResult scored against the target."""
    r = _registered()
    fresh = DomainResult(domain="googel.com", kind=PermutationType.TYPO, resolves=True)

    with (
        _patch_triage("Resolver") as MockResolver,
        _patch_triage("scoring") as mock_scoring,
    ):
        # Make Resolver.check_one return the fresh result
        mock_instance = AsyncMock()
        mock_instance.check_one.return_value = fresh
        MockResolver.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        MockResolver.return_value.__aexit__ = AsyncMock(return_value=False)

        scored = fresh.model_copy(update={"risk_score": 28, "risk_level": RiskLevel.LOW})
        mock_scoring.score.return_value = scored

        result = _rescan_result(r, "example.com", check_http=True, console=MagicMock())

    assert result.domain == "googel.com"
    mock_scoring.score.assert_called_once_with(
        fresh, "example.com", target_title=mock_instance.target_title
    )


# ---------------------------------------------------------------------------
# _suggest_defensive_whitelist (Task 07)
# ---------------------------------------------------------------------------


def _defensive() -> DomainResult:
    return DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        is_likely_defensive=True,
        redirects_to="https://google.com",
        risk_score=30,
        risk_level=RiskLevel.LOW,
    )


def test_suggest_defensive_whitelist_silent_when_no_defensive():
    """No defensive domains → function is a no-op."""
    report = ScanReport(target="example.com", total_permutations=5)
    console = MagicMock()
    _suggest_defensive_whitelist(report, console)
    console.print.assert_not_called()


def test_suggest_defensive_whitelist_prints_message():
    """Defensive domain found → prints a warning with the count."""
    r = _defensive()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with _patch_triage("_confirm", return_value=False):
        console = MagicMock()
        _suggest_defensive_whitelist(report, console)
    assert console.print.called
    printed = " ".join(str(c) for c in console.print.call_args_list)
    assert "1" in printed


def test_suggest_defensive_whitelist_writes_file_on_yes(tmp_path, monkeypatch):
    """Answering y writes the defensive domain to whitelist.txt in cwd."""
    monkeypatch.chdir(tmp_path)
    r = _defensive()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with _patch_triage("_confirm", return_value=True):
        _suggest_defensive_whitelist(report, MagicMock())
    wl = tmp_path / "whitelist.txt"
    assert wl.exists()
    assert "googel.com" in wl.read_text()


def test_suggest_defensive_whitelist_no_file_on_no(tmp_path, monkeypatch):
    """Answering n writes nothing."""
    monkeypatch.chdir(tmp_path)
    r = _defensive()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with _patch_triage("_confirm", return_value=False):
        _suggest_defensive_whitelist(report, MagicMock())
    assert not (tmp_path / "whitelist.txt").exists()


def test_suggest_defensive_whitelist_skips_already_present_entries(tmp_path, monkeypatch):
    """A domain already in whitelist.txt is not duplicated; the "all already
    in whitelist" message is printed instead."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "whitelist.txt").write_text("googel.com\n", encoding="utf-8")
    r = _defensive()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    console = MagicMock()
    with _patch_triage("_confirm", return_value=True):
        _suggest_defensive_whitelist(report, console)
    printed = " ".join(str(c) for c in console.print.call_args_list)
    assert "already in whitelist" in printed


def test_suggest_defensive_whitelist_adds_newline_before_appending(tmp_path, monkeypatch):
    """A whitelist.txt lacking a trailing newline gets one inserted before the
    new entry instead of fusing with the file's last line (regression test for
    commit 728df09 — the file here has no test coverage before this)."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "whitelist.txt").write_text("existing.com", encoding="utf-8")  # no trailing \n
    r = _defensive()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with _patch_triage("_confirm", return_value=True):
        _suggest_defensive_whitelist(report, MagicMock())
    content = (tmp_path / "whitelist.txt").read_text(encoding="utf-8")
    assert content == "existing.com\ngoogel.com\n"


def test_suggest_defensive_whitelist_handles_write_error(tmp_path, monkeypatch):
    """A write failure while updating whitelist.txt is reported, not raised."""
    monkeypatch.chdir(tmp_path)
    r = _defensive()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    console = MagicMock()
    with (
        _patch_triage("_confirm", return_value=True),
        patch.object(Path, "open", side_effect=OSError("permission denied")),
    ):
        _suggest_defensive_whitelist(report, console)
    printed = " ".join(str(c) for c in console.print.call_args_list)
    assert "permission denied" in printed
