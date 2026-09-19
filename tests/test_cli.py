"""Tests for CLI helper logic."""

from __future__ import annotations

import io
import logging
import re
import runpy
import sys
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from otacon import cli
from otacon.cli import app

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def plain(output: str) -> str:
    """Strips ANSI styling so help text can be asserted on as plain text.

    Typer styles an option name as several separate spans — '--fail-on' is
    emitted as '-' + '-fail' + '-on', each individually wrapped in escape
    codes — so the literal string is absent from coloured output. Colour is off
    in a plain local terminal but forced on in CI, which is exactly the kind of
    gap that only ever fails after a push.
    """
    return _ANSI_RE.sub("", output)


def test_load_exclusions_parses_comma_separated_values() -> None:
    exclusions = cli._load_exclusions("good.com,EXAMPLE.COM", None)
    assert exclusions == {"good.com", "example.com"}


def test_load_exclusions_reads_file(tmp_path: Path) -> None:
    file_path = tmp_path / "whitelist.txt"
    file_path.write_text("# comment\ntrusted.com\n example.com \n")

    exclusions = cli._load_exclusions(None, file_path)
    assert exclusions == {"trusted.com", "example.com"}


def test_load_exclusions_strips_www_so_the_entry_can_match() -> None:
    """A 'www.'-prefixed whitelist entry must suppress the bare domain.

    Exclusions are only ever matched against permutation output, which never
    carries a 'www.' prefix, so keeping it made such an entry silently dead:
    '--exclude www.example.net' still reported example.net as a lookalike.
    """
    from otacon import permutations

    exclusions = cli._load_exclusions("www.example.net", None)
    assert exclusions == {"example.net"}

    generated = {p.domain for p in permutations.generate("example.com", exclude=exclusions)}
    assert "example.net" not in generated


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

    async def fake_run_scan(domain, concurrency, check_http, exclude=None, quiet=False, **kwargs):
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

    async def fake_empty(domain, concurrency, check_http, exclude=None, quiet=False, **kwargs):
        return ScanReport(target=domain, total_permutations=10)

    monkeypatch.setattr("otacon.cli._run_scan", fake_empty)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "google.com", "--fail-on", "low"])
    assert result.exit_code == 0


def test_scan_fail_on_help_shows_valid_choices() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert "--fail-on" in plain(result.output)


def test_version_flag_prints_version() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "otacon" in result.output


# ---------------------------------------------------------------------------
# generate command
# ---------------------------------------------------------------------------


def test_generate_command_prints_variants() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["generate", "example.com", "--limit", "5"])
    assert result.exit_code == 0
    # Output should include the limit/total summary line
    assert "variants for" in result.output


def test_generate_command_writes_wordlist(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(app, ["generate", "example.com", "-o", "wordlist.txt"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "wordlist.txt").exists()
    lines = (tmp_path / "wordlist.txt").read_text().splitlines()
    assert lines  # at least one variant


def test_generate_command_refuses_unsafe_output_path(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["generate", "example.com", "-o", "/etc/evil.txt"])
    # Should still exit 0 (warn + skip write), not crash
    assert result.exit_code == 0
    assert "unsafe path" in result.output


def test_generate_command_rejects_invalid_domain() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["generate", "not a domain"])
    assert result.exit_code == 1


def test_generate_quiet_mode_emits_json(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--quiet", "generate", "example.com"])
    assert result.exit_code == 0
    # quiet+no-output prints a JSON array of domain strings to stdout
    import json

    payload = json.loads(result.output.splitlines()[-1])
    assert isinstance(payload, list) and payload
    assert all(isinstance(s, str) for s in payload)


# ---------------------------------------------------------------------------
# scan command — file outputs (--json / --markdown / --csv / --html)
# ---------------------------------------------------------------------------


def test_scan_writes_all_export_formats(tmp_path, monkeypatch) -> None:
    from otacon.models import ScanReport

    async def fake_run_scan(domain, concurrency, check_http, exclude=None, quiet=False, **kwargs):
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", fake_run_scan)

    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--json",
            "r.json",
            "--md",
            "r.md",
            "--csv",
            "r.csv",
            "--html",
            "r.html",
        ],
    )
    assert result.exit_code == 0, result.output
    for name in ("r.json", "r.md", "r.csv", "r.html"):
        assert (tmp_path / name).exists(), f"missing {name}: {result.output}"


def test_scan_refuses_unsafe_output_path(tmp_path, monkeypatch) -> None:
    from otacon.models import ScanReport

    async def fake_run_scan(domain, concurrency, check_http, exclude=None, quiet=False, **kwargs):
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", fake_run_scan)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "example.com", "--json", "/etc/evil.json"])
    assert result.exit_code == 0
    assert "unsafe path" in result.output


def test_scan_rejects_invalid_domain() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "not a domain"])
    assert result.exit_code == 1


def test_load_exclusions_combines_cli_and_file(tmp_path: Path) -> None:
    file_path = tmp_path / "wl.txt"
    file_path.write_text("from-file.com\n")
    out = cli._load_exclusions("from-cli.com", file_path)
    assert out == {"from-cli.com", "from-file.com"}


def test_state_default_when_obj_missing() -> None:
    """_state() must return a fresh default when ctx.obj is unset (test paths
    that invoke subcommands directly bypass the root callback)."""
    fake_ctx = type("Ctx", (), {"obj": None})()
    assert cli._state(fake_ctx).quiet is False


def test_scan_keyboard_interrupt_exits_cleanly(monkeypatch) -> None:
    """Ctrl+C during a scan should exit 1 with a message, not dump a traceback."""

    async def _interrupt(*_a, **_kw):
        raise KeyboardInterrupt

    monkeypatch.setattr("otacon.cli._run_scan", _interrupt)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "example.com"])
    assert result.exit_code == 1
    assert "Interrupted" in result.output


# ---------------------------------------------------------------------------
# _ensure_unicode_output — console encoding shim
# ---------------------------------------------------------------------------


def test_ensure_unicode_output_skips_non_textiowrapper(monkeypatch) -> None:
    """Streams that aren't a TextIOWrapper (e.g. pytest's capture proxy) are left alone."""
    monkeypatch.setattr(cli.sys, "stdout", object())
    monkeypatch.setattr(cli.sys, "stderr", object())
    cli._ensure_unicode_output()  # must not raise


def test_ensure_unicode_output_reconfigures_non_utf8_stream_on_posix(monkeypatch) -> None:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(cli.sys, "stdout", stream)
    monkeypatch.setattr(cli.sys, "stderr", stream)
    monkeypatch.setattr(cli.sys, "platform", "linux")
    cli._ensure_unicode_output()
    assert stream.errors == "replace"


def test_ensure_unicode_output_reconfigures_utf8_on_win32(monkeypatch) -> None:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(cli.sys, "stdout", stream)
    monkeypatch.setattr(cli.sys, "stderr", stream)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    cli._ensure_unicode_output()
    assert stream.encoding.lower().replace("-", "") == "utf8"


def test_ensure_unicode_output_swallows_reconfigure_errors(monkeypatch) -> None:
    class _BrokenStream(io.TextIOWrapper):
        def reconfigure(self, **kwargs):
            raise ValueError("boom")

    stream = _BrokenStream(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(cli.sys, "stdout", stream)
    monkeypatch.setattr(cli.sys, "stderr", stream)
    cli._ensure_unicode_output()  # exception must be swallowed, not propagated


# ---------------------------------------------------------------------------
# _configure_logging
# ---------------------------------------------------------------------------


def test_configure_logging_debug_attaches_rich_handler() -> None:
    cli._configure_logging(True)
    logger = logging.getLogger("otacon")
    try:
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) == 1
    finally:
        cli._configure_logging(False)  # restore quiet state for other tests


# ---------------------------------------------------------------------------
# _load_exclusions — unreadable (not merely missing) file
# ---------------------------------------------------------------------------


def test_load_exclusions_raises_for_unreadable_file(tmp_path: Path) -> None:
    # A directory can't be read_text()'d — OSError, not FileNotFoundError.
    with pytest.raises(typer.BadParameter, match="cannot read exclude-file"):
        cli._load_exclusions(None, tmp_path)


# ---------------------------------------------------------------------------
# _load_weights
# ---------------------------------------------------------------------------


def test_load_weights_returns_defaults_when_no_file() -> None:
    weights = cli._load_weights(None)
    assert isinstance(weights, cli.scoring.ScoringWeights)


def test_load_weights_loads_overrides_from_json(tmp_path: Path) -> None:
    file_path = tmp_path / "weights.json"
    file_path.write_text('{"points_mx": 99}')
    weights = cli._load_weights(file_path)
    assert weights.points_mx == 99


def test_load_weights_raises_for_missing_file() -> None:
    with pytest.raises(typer.BadParameter, match="weights-file not found"):
        cli._load_weights(Path("does-not-exist.json"))


def test_load_weights_raises_for_invalid_json(tmp_path: Path) -> None:
    file_path = tmp_path / "bad.json"
    file_path.write_text("{not valid json")
    with pytest.raises(typer.BadParameter, match="cannot read/parse weights-file"):
        cli._load_weights(file_path)


def test_load_weights_raises_clean_error_for_non_numeric_value(tmp_path: Path) -> None:
    """A `null`/list value for a weight must surface as typer.BadParameter, not
    an unhandled TypeError traceback — see scoring.ScoringWeights._apply_overrides."""
    file_path = tmp_path / "weights.json"
    file_path.write_text('{"points_mx": null}')
    with pytest.raises(typer.BadParameter, match="cannot read/parse weights-file"):
        cli._load_weights(file_path)


# ---------------------------------------------------------------------------
# _run_scan — real function body, network mocked out via a fake Resolver
# ---------------------------------------------------------------------------


class _FakeResolver:
    """Minimal async-context-manager stand-in for Resolver — no real network I/O."""

    dns_hijack_detected = False

    def __init__(self, concurrency, check_http, target) -> None:
        self.target_title = None

    async def __aenter__(self) -> _FakeResolver:
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    async def check_one(self, perm):
        from otacon.models import DomainResult

        return DomainResult(domain=perm.domain, kind=perm.kind, resolves=True)


class _HijackResolver(_FakeResolver):
    dns_hijack_detected = True


def _two_fake_perms():
    from otacon.models import Permutation, PermutationType

    return [
        Permutation(domain="evil1.example.com", kind=PermutationType.TYPO),
        Permutation(domain="evil2.example.com", kind=PermutationType.TYPO),
    ]


@pytest.mark.asyncio
async def test_run_scan_returns_empty_report_when_no_permutations(monkeypatch) -> None:
    monkeypatch.setattr(cli.permutations, "generate", lambda target, exclude=None: [])
    report = await cli._run_scan("example.com", concurrency=5, check_http=True)
    assert report.results == []
    assert report.total_permutations == 0


def _patch_scan_deps(monkeypatch, resolver_cls=_FakeResolver) -> None:
    monkeypatch.setattr(
        cli.permutations, "generate", lambda target, exclude=None: _two_fake_perms()
    )
    monkeypatch.setattr("otacon._scanner.Resolver", resolver_cls)


@pytest.mark.asyncio
async def test_run_scan_quiet_mode_collects_hits(monkeypatch) -> None:
    _patch_scan_deps(monkeypatch)
    report = await cli._run_scan("example.com", concurrency=5, check_http=True, quiet=True)
    assert report.total_permutations == 2
    assert len(report.results) == 2
    assert all(r.is_registered for r in report.results)


@pytest.mark.asyncio
async def test_run_scan_non_quiet_mode_renders_live_table(monkeypatch) -> None:
    _patch_scan_deps(monkeypatch)
    report = await cli._run_scan("example.com", concurrency=5, check_http=True, quiet=False)
    assert len(report.results) == 2


@pytest.mark.asyncio
async def test_run_scan_reports_dns_hijack_warning(monkeypatch, capsys) -> None:
    _patch_scan_deps(monkeypatch, resolver_cls=_HijackResolver)
    report = await cli._run_scan("example.com", concurrency=5, check_http=True, quiet=True)
    assert report.dns_hijack_detected is True
    assert "NXDOMAIN hijacking" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# scan command — quiet JSON + failed file writes
# ---------------------------------------------------------------------------


def test_scan_quiet_mode_emits_json(monkeypatch) -> None:
    from otacon.models import ScanReport

    async def fake_run_scan(domain, concurrency, check_http, exclude=None, quiet=False, **kwargs):
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", fake_run_scan)
    runner = CliRunner()
    result = runner.invoke(app, ["--quiet", "scan", "example.com"])
    assert result.exit_code == 0

    import json

    payload = json.loads(result.output)
    assert payload["target"] == "example.com"


def test_scan_json_write_oserror_is_reported(tmp_path: Path, monkeypatch) -> None:
    from otacon.models import ScanReport

    async def fake_run_scan(domain, concurrency, check_http, exclude=None, quiet=False, **kwargs):
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", fake_run_scan)
    (tmp_path / "r.json").mkdir()  # occupies the target path so write_text() raises OSError
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "example.com", "--json", "r.json"])
    assert result.exit_code == 0
    assert "Error saving JSON" in result.output


# ---------------------------------------------------------------------------
# generate command — failed wordlist write
# ---------------------------------------------------------------------------


def test_generate_wordlist_write_oserror_is_reported(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "wordlist.txt").mkdir()
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(app, ["generate", "example.com", "-o", "wordlist.txt"])
    assert result.exit_code == 0
    assert "Error saving wordlist" in result.output


# ---------------------------------------------------------------------------
# module entry points — `python -m otacon` / `python cli.py`
# ---------------------------------------------------------------------------


def test_main_module_entrypoint(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["otacon", "--version"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("otacon.__main__", run_name="__main__")
    assert exc.value.code == 0


@pytest.mark.filterwarnings("ignore:'otacon.cli' found in sys.modules:RuntimeWarning")
def test_cli_module_dunder_main(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["otacon", "--version"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("otacon.cli", run_name="__main__")
    assert exc.value.code == 0


# ---------------------------------------------------------------------------
# Multi-domain scan
# ---------------------------------------------------------------------------


def test_load_domains_merges_args_and_file(tmp_path: Path) -> None:
    file_path = tmp_path / "domains.txt"
    file_path.write_text("# comment\nexample.com\ngoogle.com\n")
    result = cli._load_domains(["github.com"], file_path)
    assert result == ["github.com", "example.com", "google.com"]


def test_load_domains_deduplicates(tmp_path: Path) -> None:
    file_path = tmp_path / "domains.txt"
    file_path.write_text("github.com\n")
    result = cli._load_domains(["github.com", "GITHUB.COM"], file_path)
    assert result == ["github.com"]


def test_load_domains_normalises_www() -> None:
    result = cli._load_domains(["www.github.com"], None)
    assert result == ["github.com"]


def test_load_domains_raises_for_missing_file() -> None:
    with pytest.raises(typer.BadParameter, match="domains-file not found"):
        cli._load_domains([], Path("does-not-exist.txt"))


def test_scan_multiple_positional_args_scans_each(monkeypatch) -> None:
    from otacon.models import ScanReport

    scanned: list[str] = []

    async def capturing_scan(domain, *args, **kwargs):
        scanned.append(domain)
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", capturing_scan)
    runner = CliRunner()
    runner.invoke(app, ["scan", "github.com", "example.com"])
    assert "github.com" in scanned
    assert "example.com" in scanned


def test_scan_domains_file_option(monkeypatch, tmp_path: Path) -> None:
    from otacon.models import ScanReport

    domains_file = tmp_path / "brands.txt"
    domains_file.write_text("alpha.com\nbeta.com\n")
    scanned: list[str] = []

    async def capturing_scan(domain, *args, **kwargs):
        scanned.append(domain)
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", capturing_scan)
    runner = CliRunner()
    runner.invoke(app, ["scan", "--domains-file", str(domains_file)])
    assert scanned == ["alpha.com", "beta.com"]


def test_scan_invalid_domain_in_list_is_skipped(monkeypatch) -> None:
    from otacon.models import ScanReport

    scanned: list[str] = []

    async def capturing_scan(domain, *args, **kwargs):
        scanned.append(domain)
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", capturing_scan)
    runner = CliRunner()
    runner.invoke(app, ["scan", "not_a_domain!", "valid.com"])
    assert "valid.com" in scanned
    assert "not_a_domain!" not in scanned


def test_scan_fail_on_triggers_if_any_domain_hits_threshold(monkeypatch) -> None:
    from otacon.models import DomainResult, PermutationType, ScanReport
    from otacon.theme import RiskLevel

    async def fake_run_scan(domain, *args, **kwargs):
        report = ScanReport(target=domain, total_permutations=1)
        if domain == "evil-twin.com":
            report.results.append(
                DomainResult(
                    domain="eviltwin.com",
                    kind=PermutationType.TYPO,
                    resolves=True,
                    risk_score=90,
                    risk_level=RiskLevel.CRITICAL,
                )
            )
        return report

    monkeypatch.setattr("otacon.cli._run_scan", fake_run_scan)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "clean.com", "evil-twin.com", "--fail-on", "critical"])
    assert result.exit_code == 2


def test_scan_fail_on_does_not_trigger_when_no_domain_hits_threshold(monkeypatch) -> None:
    from otacon.models import ScanReport

    async def fake_run_scan(domain, *args, **kwargs):
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", fake_run_scan)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "clean.com", "also-clean.com", "--fail-on", "critical"])
    assert result.exit_code == 0


def test_scan_exception_in_one_domain_continues_rest(monkeypatch) -> None:
    from otacon.models import ScanReport

    scanned: list[str] = []

    async def flaky_scan(domain, *args, **kwargs):
        if domain == "bad.com":
            raise RuntimeError("resolver exploded")
        scanned.append(domain)
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", flaky_scan)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "bad.com", "good.com"])
    assert "good.com" in scanned
    assert result.exit_code == 0


def test_load_domains_oserror_raises_bad_parameter(tmp_path: Path) -> None:
    with pytest.raises(typer.BadParameter, match="cannot read domains-file"):
        cli._load_domains([], tmp_path)  # directory → IsADirectoryError (OSError subclass)


def test_load_domains_empty_input_returns_empty_list() -> None:
    assert cli._load_domains([], None) == []


def test_scan_all_domains_fail_exits_1(monkeypatch) -> None:
    async def always_fail(domain, *args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("otacon.cli._run_scan", always_fail)
    result = CliRunner().invoke(app, ["scan", "bad1.com", "bad2.com"])
    assert result.exit_code == 1


def test_scan_quiet_multi_domain_emits_aggregate_json(monkeypatch) -> None:
    import json

    from otacon.models import ScanReport

    async def fake_scan(domain, *args, **kwargs):
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", fake_scan)
    result = CliRunner().invoke(app, ["--quiet", "scan", "alpha.com", "beta.com"])
    assert result.exit_code == 0
    payload = json.loads(result.output.strip())
    assert {"scanned_at", "domains", "summary"} == set(payload.keys())


def test_scan_multi_json_flag_writes_aggregate_format(monkeypatch, tmp_path: Path) -> None:
    import json

    from otacon.models import ScanReport

    async def fake_scan(domain, *args, **kwargs):
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", fake_scan)
    monkeypatch.chdir(tmp_path)
    CliRunner().invoke(app, ["scan", "a.com", "b.com", "--json", "out.json"])
    payload = json.loads((tmp_path / "out.json").read_text())
    assert "summary" in payload and "domains" in payload


def test_scan_multi_html_flag_writes_aggregate_format(monkeypatch, tmp_path: Path) -> None:
    from otacon.models import ScanReport

    async def fake_scan(domain, *args, **kwargs):
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", fake_scan)
    monkeypatch.chdir(tmp_path)
    CliRunner().invoke(app, ["scan", "a.com", "b.com", "--html", "out.html"])
    content = (tmp_path / "out.html").read_text()
    assert "Summary" in content and "Multi-domain" in content


def test_scan_multi_markdown_warns_not_supported(monkeypatch) -> None:
    from otacon.models import ScanReport

    async def fake_scan(domain, *args, **kwargs):
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", fake_scan)
    result = CliRunner().invoke(app, ["scan", "a.com", "b.com", "--markdown", "out.md"])
    assert "not supported" in result.output


def test_scan_multi_csv_warns_not_supported(monkeypatch) -> None:
    from otacon.models import ScanReport

    async def fake_scan(domain, *args, **kwargs):
        return ScanReport(target=domain, total_permutations=0)

    monkeypatch.setattr("otacon.cli._run_scan", fake_scan)
    result = CliRunner().invoke(app, ["scan", "a.com", "b.com", "--csv", "out.csv"])
    assert "not supported" in result.output


def test_scan_quiet_emits_single_report_when_only_one_domain_survives(monkeypatch) -> None:
    """Two domains requested, one unscannable — stdout must still carry a report.

    The quiet-mode emitters used to key off `len(domains)` for the single case and
    `len(all_reports)` for the aggregate one, so a partial failure fell between
    both branches and printed nothing at all.
    """
    import json

    from otacon.models import ScanReport

    async def fake_scan(domain, *args, **kwargs):
        if domain == "beta.com":
            raise RuntimeError("boom")
        return ScanReport(target=domain, total_permutations=3)

    monkeypatch.setattr("otacon.cli._run_scan", fake_scan)
    result = CliRunner().invoke(app, ["--quiet", "scan", "alpha.com", "beta.com"])
    assert result.exit_code == 0
    payload = json.loads(result.output.strip())
    # Single-report shape (not the aggregate envelope), for the one that worked.
    assert payload["target"] == "alpha.com"


def test_help_option_names_survive_forced_colour(monkeypatch) -> None:
    """Guards the CI-only failure mode: colour splits option names across spans.

    With colour on, Typer emits '--fail-on' as three separately styled spans, so
    asserting on the raw output passes locally (colour off) and fails in CI
    (colour forced). Every help assertion must go through plain().
    """
    monkeypatch.setenv("FORCE_COLOR", "1")
    result = CliRunner().invoke(app, ["scan", "--help"])

    assert "--fail-on" in plain(result.output)
    assert "--domains-file" in plain(result.output)
