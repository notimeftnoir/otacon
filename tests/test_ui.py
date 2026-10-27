"""Tests for the refreshed terminal UI: splash, verdict card, live view, dossier, hints."""

from __future__ import annotations

import random
from io import StringIO

from rich.console import Console

from otacon import _scanner, _splash, reporters
from otacon.interactive import _dossier
from otacon.models import DomainResult, PermutationType, ScanReport
from otacon.theme import OTACON_THEME, WORDMARK, RiskLevel, gradient, gradient_color


def _console(**kw: object) -> tuple[Console, StringIO]:
    buf = StringIO()
    return Console(file=buf, theme=OTACON_THEME, width=120, **kw), buf  # type: ignore[arg-type]


def _hit(score: int, level: RiskLevel, **kw: object) -> DomainResult:
    return DomainResult(
        domain=f"ex{score}.com",
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=score,
        risk_level=level,
        **kw,  # type: ignore[arg-type]
    )


# --- theme ------------------------------------------------------------------


def test_gradient_endpoints_match_stops() -> None:
    assert gradient_color(0.0) == "#00d7af"
    assert gradient_color(1.0) == "#5f8fff"
    assert gradient("abc").plain == "abc"


# --- splash -----------------------------------------------------------------


def test_animation_disabled_off_terminal_and_by_env(monkeypatch) -> None:
    console, _ = _console()
    assert not _splash.animations_enabled(console)  # StringIO is not a TTY
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("OTACON_NO_ANIMATION", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    tty, _ = _console(force_terminal=True, color_system="truecolor")
    assert _splash.animations_enabled(tty)
    monkeypatch.setenv("OTACON_NO_ANIMATION", "1")
    assert not _splash.animations_enabled(tty)


def test_splash_decodes_to_the_wordmark() -> None:
    rng = random.Random(0)
    first = _splash._frame(0, rng).plain
    last = _splash._frame(_splash._FRAMES - 1, rng).plain
    assert WORDMARK not in first
    assert WORDMARK in last


def test_play_intro_off_terminal_prints_static_banner_only() -> None:
    console, buf = _console()
    _splash.play_intro(console)
    assert WORDMARK in buf.getvalue()


# --- verdict card -----------------------------------------------------------


def test_headline_escalates_with_worst_level() -> None:
    clean = ScanReport(target="example.com", total_permutations=10)
    assert reporters._headline(clean)[0] == "ok"
    mild = ScanReport(target="example.com", results=[_hit(20, RiskLevel.LOW)])
    assert reporters._headline(mild)[0] == "warn"
    bad = ScanReport(target="example.com", results=[_hit(90, RiskLevel.CRITICAL)])
    style, headline, _ = reporters._headline(bad)
    assert style == "danger" and "1 lookalike of example.com looks dangerous" in headline


def test_distribution_keeps_a_lone_critical_visible() -> None:
    hits = [_hit(90, RiskLevel.CRITICAL)] + [_hit(1, RiskLevel.SAFE) for _ in range(200)]
    console, buf = _console()
    console.print(reporters._distribution(hits))
    assert RiskLevel.CRITICAL.icon in buf.getvalue()
    assert "1 critical" in buf.getvalue() and "200 harmless" in buf.getvalue()


def test_why_lists_strongest_reasons_without_points() -> None:
    r = _hit(
        60,
        RiskLevel.HIGH,
        risk_reasons=[
            "technique: typo (+20)",
            "resolves to an IP (+10)",
            "has an MX record — ready for email phishing (+15)",
            "registered 3 days ago (+25)",
        ],
    )
    assert reporters._why(r) == (
        "registered 3 days ago · has an MX record — ready for email phishing"
    )


def test_live_table_caps_rows_and_says_how_many_are_hidden() -> None:
    hits = [_hit(i, RiskLevel.MEDIUM) for i in range(12)]
    table = reporters.build_live_table(hits, "example.com", limit=8)
    assert table.row_count == 8
    assert table.caption is not None and "+4 more" in str(table.caption)


# --- scanner ----------------------------------------------------------------


def test_tally_counts_dangerous_hits() -> None:
    assert "nothing registered" in _scanner._tally([])
    tally = _scanner._tally([_hit(90, RiskLevel.CRITICAL), _hit(20, RiskLevel.LOW)])
    assert "2 registered" in tally and "1 dangerous" in tally


# --- dossier ----------------------------------------------------------------


def test_dossier_explains_signals_and_never_parses_hostile_markup() -> None:
    r = _hit(
        85,
        RiskLevel.CRITICAL,
        has_mx=True,
        mx_records=["mx.ex85.com"],
        http_status=200,
        page_title="[/][link=https://evil.example]Login[/link]",
        ip_addresses=["203.0.113.9"],
    )
    console, buf = _console()
    console.print(_dossier(r))
    out = buf.getvalue()
    assert "[link=https://evil.example]Login[/link]" in out
    assert "can send email" in out and "203.0.113.9" in out


# --- next steps ---------------------------------------------------------------


def test_next_steps_skip_what_the_user_already_did(monkeypatch) -> None:
    from otacon import cli

    console, buf = _console()
    monkeypatch.setattr(cli, "console", console)
    report = ScanReport(target="example.com", results=[_hit(90, RiskLevel.CRITICAL)])
    cli._print_next_steps({"example.com": report}, html_written=True, ci_gated=False)
    out = buf.getvalue()
    assert "--html" not in out
    assert "guided mode" in out and "--fail-on high" in out
