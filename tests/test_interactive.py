"""Tests for the interactive mode module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from otacon.interactive import (
    _action_loop,
    _confirm,
    _export_result,
    _interactive_generate,
    _interactive_scan,
    _rescan_result,
    _show_whois,
    _suggest_defensive_whitelist,
    _validate_domain,
    _validate_limit,
    run,
)
from otacon.models import (
    DomainResult,
    Permutation,
    PermutationType,
    ScanReport,
)
from otacon.theme import RiskLevel

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


def test_validate_domain_no_tld_allowed():
    assert _validate_domain("example") is True


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
    with patch("otacon.interactive.questionary") as mock_q:
        mock_q.text.return_value.ask.return_value = None
        run(MagicMock())


def test_run_exits_cleanly_on_mode_ctrl_c():
    """Ctrl+C on mode selection must exit without raising."""
    with patch("otacon.interactive.questionary") as mock_q:
        mock_q.text.return_value.ask.return_value = "example.com"
        mock_q.select.return_value.ask.return_value = None
        run(MagicMock())


def test_run_routes_to_scan(monkeypatch):
    """Mode=scan must call _interactive_scan."""
    called = {}

    def fake_scan(domain, console):
        called["domain"] = domain

    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._interactive_scan", fake_scan):
        mock_q.text.return_value.ask.return_value = "  example.com  "
        mock_q.select.return_value.ask.return_value = "scan"
        run(MagicMock())

    assert called["domain"] == "example.com"


def test_run_routes_to_generate(monkeypatch):
    """Mode=generate must call _interactive_generate."""
    called = {}

    def fake_generate(domain, console):
        called["domain"] = domain

    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._interactive_generate", fake_generate):
        mock_q.text.return_value.ask.return_value = "example.com"
        mock_q.select.return_value.ask.return_value = "generate"
        run(MagicMock())

    assert called["domain"] == "example.com"


def test_interactive_generate_prints_variants():
    """generate branch must render variants to console."""
    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive.permutations") as mock_perms:
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
    with patch("otacon.interactive.questionary") as mock_q:
        mock_q.text.return_value.ask.return_value = None
        console = MagicMock()
        _interactive_generate("example.com", console)
        console.print.assert_not_called()


def test_interactive_generate_respects_limit():
    """A non-zero limit must cap the printed variants."""
    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive.permutations") as mock_perms:
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
    with patch("otacon.interactive._pt_prompt", return_value="y"):
        assert _confirm("Continue?") is True


def test_confirm_returns_false_for_n():
    """_confirm returns False when user types n."""
    with patch("otacon.interactive._pt_prompt", return_value="n"):
        assert _confirm("Continue?") is False


def test_confirm_returns_false_for_enter():
    """_confirm defaults to False when user presses Enter (empty input)."""
    with patch("otacon.interactive._pt_prompt", return_value=""):
        assert _confirm("Continue?") is False


def test_confirm_returns_none_on_ctrl_c():
    """_confirm returns None on KeyboardInterrupt (Ctrl+C)."""
    with patch("otacon.interactive._pt_prompt", side_effect=KeyboardInterrupt):
        assert _confirm("Continue?") is None


def test_interactive_scan_full_calls_render_table(monkeypatch, tmp_path):
    """Full scan (HTTP) must call reporters.render_table with correct params."""
    monkeypatch.chdir(tmp_path)
    mock_report = ScanReport(target="example.com", total_permutations=0)

    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._confirm", return_value=False), \
         patch("otacon.interactive._scan", new_callable=AsyncMock) as mock_scan, \
         patch("otacon.interactive.reporters") as mock_reporters:
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

    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._confirm", return_value=False), \
         patch("otacon.interactive._scan", new_callable=AsyncMock) as mock_scan, \
         patch("otacon.interactive.reporters"):
        mock_q.select.return_value.ask.return_value = "dns"
        mock_scan.return_value = mock_report
        _interactive_scan("example.com", MagicMock())

    mock_scan.assert_called_once_with(
        "example.com", concurrency=50, check_http=False,
        console=mock_scan.call_args[1]["console"], exclude=None,
    )


def test_interactive_scan_ctrl_c_on_network():
    """Ctrl+C on network selection must exit without raising."""
    with patch("otacon.interactive.questionary") as mock_q:
        mock_q.select.return_value.ask.return_value = None
        _interactive_scan("example.com", MagicMock())


def test_interactive_scan_ctrl_c_on_show_all():
    """Ctrl+C on show-all must exit without raising."""
    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._confirm", return_value=None), \
         patch("otacon.interactive._scan", new_callable=AsyncMock):
        mock_q.select.return_value.ask.return_value = "full"
        _interactive_scan("example.com", MagicMock())


# ---------------------------------------------------------------------------
# Action loop (Task 06)
# ---------------------------------------------------------------------------

def test_action_loop_skips_when_no_registered():
    """Empty report → no prompt shown."""
    with patch("otacon.interactive.questionary") as mock_q:
        report = ScanReport(target="example.com", total_permutations=5)
        _action_loop(report, "example.com", MagicMock(), check_http=True)
        mock_q.select.assert_not_called()


def test_action_loop_ctrl_c_on_domain_picker():
    """Ctrl+C on domain picker exits cleanly."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with patch("otacon.interactive.questionary") as mock_q:
        mock_q.select.return_value.ask.return_value = None
        _action_loop(report, "example.com", MagicMock(), check_http=True)


def test_action_loop_quit_choice_returns_title_string():
    """Selecting '── quit ──' returns its title (not None) in questionary 2.x; must exit cleanly."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with patch("otacon.interactive.questionary") as mock_q:
        mock_q.select.return_value.ask.return_value = "── quit ──"
        _action_loop(report, "example.com", MagicMock(), check_http=True)


def test_action_loop_quit_from_action_menu():
    """Quit from action menu exits loop."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with patch("otacon.interactive.questionary") as mock_q:
        mock_q.select.return_value.ask.side_effect = [r, "quit"]
        _action_loop(report, "example.com", MagicMock(), check_http=True)


def test_action_loop_ctrl_c_from_action_menu():
    """None from action menu exits loop."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with patch("otacon.interactive.questionary") as mock_q:
        mock_q.select.return_value.ask.side_effect = [r, None]
        _action_loop(report, "example.com", MagicMock(), check_http=True)


def test_action_loop_back_returns_to_domain_picker():
    """Back action returns to domain picker (outer loop)."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with patch("otacon.interactive.questionary") as mock_q:
        # back → domain picker again → None (Ctrl+C)
        mock_q.select.return_value.ask.side_effect = [r, "back", None]
        _action_loop(report, "example.com", MagicMock(), check_http=True)
        assert mock_q.select.return_value.ask.call_count == 3


def test_action_loop_open_calls_webbrowser():
    """Open action calls webbrowser.open with the correct URL."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive.webbrowser") as mock_wb:
        mock_q.select.return_value.ask.side_effect = [r, "open", "quit"]
        _action_loop(report, "example.com", MagicMock(), check_http=True)
    mock_wb.open.assert_called_once_with("https://googel.com")


def test_action_loop_whois_calls_show_whois():
    """Whois action calls _show_whois with the selected result."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._show_whois") as mock_show:
        mock_q.select.return_value.ask.side_effect = [r, "whois", "quit"]
        _action_loop(report, "example.com", MagicMock(), check_http=True)
    mock_show.assert_called_once_with(r, mock_show.call_args[0][1])


def test_action_loop_export_calls_export_result():
    """Export action calls _export_result with the selected result."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._export_result") as mock_export:
        mock_q.select.return_value.ask.side_effect = [r, "export", "quit"]
        _action_loop(report, "example.com", MagicMock(), check_http=True)
    assert mock_export.called


def test_action_loop_allow_removes_domain_from_next_iteration():
    """Allow adds domain to session whitelist → domain absent from next outer loop."""
    r = _registered()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with patch("otacon.interactive.questionary") as mock_q:
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
    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._rescan_result", return_value=updated) as mock_rescan, \
         patch("otacon.interactive.reporters"):
        mock_q.select.return_value.ask.side_effect = [r, "rescan", "quit"]
        _action_loop(report, "example.com", MagicMock(), check_http=False)
    assert mock_rescan.called
    assert report.results[0].risk_score == 75


def test_action_loop_called_after_render_in_interactive_scan():
    """_interactive_scan calls _action_loop after render_table."""
    mock_report = ScanReport(target="example.com", total_permutations=0)
    called = {}

    def fake_loop(report, domain, console, check_http):
        called["ran"] = True

    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._confirm", return_value=False), \
         patch("otacon.interactive._scan", new_callable=AsyncMock) as mock_scan, \
         patch("otacon.interactive.reporters"), \
         patch("otacon.interactive._action_loop", fake_loop):
        mock_q.select.return_value.ask.return_value = "full"
        mock_scan.return_value = mock_report
        _interactive_scan("example.com", MagicMock())

    assert called.get("ran") is True


# ---------------------------------------------------------------------------
# _show_whois
# ---------------------------------------------------------------------------

def test_show_whois_uses_cached_data_without_fetch():
    """_show_whois shows cached created_at from result — no asyncio.run call."""
    from datetime import datetime, timezone
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        created_at=datetime(2024, 3, 1, tzinfo=timezone.utc),
        age_days=90,
    )
    with patch("otacon.interactive.asyncio") as mock_asyncio:
        console = MagicMock()
        _show_whois(r, console)
    mock_asyncio.run.assert_not_called()
    assert console.print.called


def test_show_whois_fetches_when_no_cache():
    """_show_whois fetches WHOIS when created_at is None."""
    from datetime import datetime, timezone
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)

    async def _fake_fetch(domain):
        return (datetime(2024, 1, 1, tzinfo=timezone.utc), 150)

    with patch("otacon.interactive.fetch_domain_age", _fake_fetch):
        console = MagicMock()
        _show_whois(r, console)
    assert console.print.called


def test_show_whois_shows_unavailable_on_failed_lookup():
    """_show_whois prints 'unavailable' when fetch returns (None, None)."""
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)

    async def _fake_fetch(domain):
        return (None, None)

    with patch("otacon.interactive.fetch_domain_age", _fake_fetch):
        console = MagicMock()
        _show_whois(r, console)
    printed = " ".join(str(c) for c in console.print.call_args_list)
    assert "unavailable" in printed


# ---------------------------------------------------------------------------
# _export_result
# ---------------------------------------------------------------------------

def test_export_result_writes_json_to_file(tmp_path):
    """_export_result saves valid JSON for the given domain result."""
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)
    out_file = tmp_path / "googel_com.json"
    with patch("otacon.interactive.questionary") as mock_q:
        mock_q.text.return_value.ask.return_value = str(out_file)
        _export_result(r, MagicMock())
    assert out_file.exists()
    import json
    data = json.loads(out_file.read_text())
    assert data["domain"] == "googel.com"


def test_export_result_ctrl_c_exits_cleanly():
    """Ctrl+C on filename prompt exits without error."""
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)
    with patch("otacon.interactive.questionary") as mock_q:
        mock_q.text.return_value.ask.return_value = None
        _export_result(r, MagicMock())  # must not raise


# ---------------------------------------------------------------------------
# _rescan_result
# ---------------------------------------------------------------------------

def test_rescan_result_returns_scored_domain_result():
    """_rescan_result returns a DomainResult scored against the target."""
    r = _registered()
    fresh = DomainResult(domain="googel.com", kind=PermutationType.TYPO, resolves=True)

    with patch("otacon.interactive.Resolver") as MockResolver, \
         patch("otacon.interactive.scoring") as mock_scoring:
        # Make Resolver.check_one return the fresh result
        mock_instance = AsyncMock()
        mock_instance.check_one.return_value = fresh
        MockResolver.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        MockResolver.return_value.__aexit__ = AsyncMock(return_value=False)

        scored = fresh.model_copy(update={"risk_score": 28, "risk_level": RiskLevel.LOW})
        mock_scoring.score.return_value = scored

        result = _rescan_result(r, "example.com", check_http=True, console=MagicMock())

    assert result.domain == "googel.com"
    mock_scoring.score.assert_called_once_with(fresh, "example.com")


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
    with patch("otacon.interactive._confirm", return_value=False):
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
    with patch("otacon.interactive._confirm", return_value=True):
        _suggest_defensive_whitelist(report, MagicMock())
    wl = tmp_path / "whitelist.txt"
    assert wl.exists()
    assert "googel.com" in wl.read_text()


def test_suggest_defensive_whitelist_no_file_on_no(tmp_path, monkeypatch):
    """Answering n writes nothing."""
    monkeypatch.chdir(tmp_path)
    r = _defensive()
    report = ScanReport(target="example.com", total_permutations=5, results=[r])
    with patch("otacon.interactive._confirm", return_value=False):
        _suggest_defensive_whitelist(report, MagicMock())
    assert not (tmp_path / "whitelist.txt").exists()
