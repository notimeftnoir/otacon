"""Tests for the interactive mode module."""
from __future__ import annotations

import pytest

from otacon.interactive import _validate_domain, _validate_limit


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


from unittest.mock import MagicMock, patch


def test_run_exits_cleanly_on_domain_ctrl_c():
    """Ctrl+C on domain input must exit without raising."""
    with patch("otacon.interactive.questionary") as mock_q:
        mock_q.text.return_value.ask.return_value = None
        console = MagicMock()
        from otacon.interactive import run
        run(console)  # must not raise


def test_run_exits_cleanly_on_mode_ctrl_c():
    """Ctrl+C on mode selection must exit without raising."""
    with patch("otacon.interactive.questionary") as mock_q:
        mock_q.text.return_value.ask.return_value = "example.com"
        mock_q.select.return_value.ask.return_value = None
        console = MagicMock()
        from otacon.interactive import run
        run(console)  # must not raise


def test_run_routes_to_scan(monkeypatch):
    """Mode=scan must call _interactive_scan."""
    called = {}

    def fake_scan(domain, console):
        called["domain"] = domain
        called["console"] = console

    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._interactive_scan", fake_scan):
        mock_q.text.return_value.ask.return_value = "  example.com  "
        mock_q.select.return_value.ask.return_value = "scan"
        console = MagicMock()
        from otacon.interactive import run
        run(console)

    assert called["domain"] == "example.com"  # stripped


def test_run_routes_to_generate(monkeypatch):
    """Mode=generate must call _interactive_generate."""
    called = {}

    def fake_generate(domain, console):
        called["domain"] = domain

    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._interactive_generate", fake_generate):
        mock_q.text.return_value.ask.return_value = "example.com"
        mock_q.select.return_value.ask.return_value = "generate"
        console = MagicMock()
        from otacon.interactive import run
        run(console)

    assert called["domain"] == "example.com"


def test_interactive_generate_prints_variants():
    """generate branch must render variants to console."""
    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive.permutations") as mock_perms:

        from otacon.models import Permutation, PermutationType
        mock_perms.generate.return_value = [
            Permutation(domain="exmaple.com", kind=PermutationType.TYPO, note="swap"),
            Permutation(domain="examplee.com", kind=PermutationType.TYPO, note="dup"),
        ]
        mock_q.text.return_value.ask.return_value = "0"  # limit=0 → show all

        console = MagicMock()
        from otacon.interactive import _interactive_generate
        _interactive_generate("example.com", console)

    assert console.print.called


def test_interactive_generate_ctrl_c_on_limit():
    """Ctrl+C on limit input must exit without raising."""
    with patch("otacon.interactive.questionary") as mock_q:
        mock_q.text.return_value.ask.return_value = None
        console = MagicMock()
        from otacon.interactive import _interactive_generate
        _interactive_generate("example.com", console)
        console.print.assert_not_called()


def test_interactive_generate_respects_limit():
    """A non-zero limit must cap the printed variants."""
    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive.permutations") as mock_perms:

        from otacon.models import Permutation, PermutationType
        mock_perms.generate.return_value = [
            Permutation(domain=f"ex{i}mple.com", kind=PermutationType.TYPO, note="x")
            for i in range(10)
        ]
        mock_q.text.return_value.ask.return_value = "3"

        console = MagicMock()
        from otacon.interactive import _interactive_generate
        _interactive_generate("example.com", console)

    # header print + 3 variant prints + 1 "... and N more" print = 5 calls
    assert console.print.call_count == 5


from unittest.mock import AsyncMock


def test_interactive_scan_full_calls_render_table():
    """Full scan (HTTP) must call reporters.render_table with correct params."""
    from otacon.models import ScanReport

    mock_report = ScanReport(target="example.com", total_permutations=0)

    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._scan", new_callable=AsyncMock) as mock_scan, \
         patch("otacon.interactive.reporters") as mock_reporters:

        mock_q.select.return_value.ask.side_effect = ["full", False]
        mock_scan.return_value = mock_report

        console = MagicMock()
        from otacon.interactive import _interactive_scan
        _interactive_scan("example.com", console)

    mock_scan.assert_called_once_with(
        "example.com", concurrency=50, check_http=True, console=console
    )
    mock_reporters.render_table.assert_called_once_with(mock_report, console, show_safe=False)


def test_interactive_scan_dns_only():
    """DNS-only scan must pass check_http=False."""
    from otacon.models import ScanReport

    mock_report = ScanReport(target="example.com", total_permutations=0)

    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._scan", new_callable=AsyncMock) as mock_scan, \
         patch("otacon.interactive.reporters") as mock_reporters:

        mock_q.select.return_value.ask.side_effect = ["dns", False]
        mock_scan.return_value = mock_report

        console = MagicMock()
        from otacon.interactive import _interactive_scan
        _interactive_scan("example.com", console)

    mock_scan.assert_called_once_with(
        "example.com", concurrency=50, check_http=False, console=console
    )


def test_interactive_scan_ctrl_c_on_network():
    """Ctrl+C on network selection must exit without raising."""
    with patch("otacon.interactive.questionary") as mock_q:
        mock_q.select.return_value.ask.return_value = None
        console = MagicMock()
        from otacon.interactive import _interactive_scan
        _interactive_scan("example.com", console)


def test_interactive_scan_ctrl_c_on_show_all():
    """Ctrl+C on show-all confirm must exit without raising."""
    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._scan", new_callable=AsyncMock):

        mock_q.select.return_value.ask.side_effect = ["full", None]

        console = MagicMock()
        from otacon.interactive import _interactive_scan
        _interactive_scan("example.com", console)
