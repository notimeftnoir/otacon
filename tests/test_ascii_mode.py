"""`--ascii` must reach every surface, not only the brand mark.

The glyph budget in ``ui.glyphs.SAFE`` is checked against the *source* by
``test_theme.py``: it answers "is this codepoint allowed", which is a different
question from "does it get degraded before it reaches the terminal". Nothing
asked the second one, so the surfaces drifted apart — the static banner swapped
U+041E for a plain O while the intro animation printed it raw, the engine's own
warnings carried U+26A0, and six separators in the triage console were literals.

A terminal in ASCII mode shows a replacement character for every one of those,
which is the silent visual failure the budget exists to prevent. These tests
render each surface and assert the bytes, so the claim is checked rather than
documented.
"""

from __future__ import annotations

import io
import random

import pytest
from rich.console import Console

from otacon.core.models import DomainResult, Permutation, ScanOptions, ScanReport
from otacon.core.types import PermutationType, RiskLevel
from otacon.ui.caps import GlyphLevel
from otacon.ui.tokens import MIDNIGHT


@pytest.fixture(autouse=True)
def ascii_terminal(monkeypatch):
    """Pins the glyph level to ASCII for the duration of a test."""
    from otacon.utils import theme

    monkeypatch.setenv("OTACON_ASCII", "1")
    monkeypatch.setattr(theme, "_glyphs", GlyphLevel.ASCII)
    monkeypatch.setattr(theme, "_palette", MIDNIGHT)


@pytest.fixture
def row() -> DomainResult:
    """One row carrying every signal, so no branch is skipped for want of data."""
    raw = DomainResult(
        domain="examp1e.com",
        kind=PermutationType.HOMOGLYPH,
        note="visually identical character",
        resolves=True,
        ip_addresses=["93.184.216.34"],
        has_mx=True,
        mx_records=["mx.examp1e.com"],
        has_ssl=True,
        ssl_issuer="R3",
        ssl_cert_age_days=2,
        ssl_san_matches=False,
        http_status=200,
        redirects_to="https://example.com/",
        page_title="Example",
        age_days=3,
        has_login_form=True,
        dnsbl_listed=True,
        dnsbl_source="Spamhaus DBL (phishing)",
        favicon_matches_target=True,
        favicon_hash=-1234,
        has_spf=True,
        spf_record="v=spf1 -all",
        is_mail_spoofable=True,
        is_parked=False,
    )
    # Scored by the real engine, not by hand: its reason strings carry em-dashes
    # that an invented list would not, and that is exactly the text the dossier
    # and the console's "why" section print.
    from otacon.scoring.engine import score

    return score(raw, "example.com", target_title="Example Domain")


@pytest.fixture
def report(row: DomainResult) -> ScanReport:
    # Two rows on purpose: one carrying every signal, and one with nothing
    # known about it. A real scan is mostly the second kind, and a fixture made
    # only of the first never renders the "no data" dash that format_age,
    # _age_cell and the signal checklist all reach for.
    unknown = DomainResult(
        domain="exarnple.com",
        kind=PermutationType.TYPO,
        resolves=True,
        ip_addresses=["198.51.100.7"],
        risk_score=28,
        risk_level=RiskLevel.LOW,
    )
    return ScanReport(
        target="example.com",
        total_permutations=12,
        results=[row, unknown],
        dns_queries=24,
        dns_failures=9,
        options=ScanOptions(),
    )


def _theme():
    """The Rich theme the CLI actually builds its console with."""
    from otacon.utils.theme import OTACON_THEME

    return OTACON_THEME


def _rendered(renderable) -> str:
    """What Rich would put on a terminal for *renderable*."""
    console = Console(file=io.StringIO(), width=140, legacy_windows=False, theme=_theme())
    console.print(renderable)
    return console.file.getvalue()


def _assert_ascii(text: str, what: str) -> None:
    stray = sorted({c for c in text if ord(c) > 127})
    assert not stray, (
        f"{what} puts {[f'U+{ord(c):04X} {c}' for c in stray]} on an ASCII terminal. "
        "Wrap the chrome in utils.theme.glyph() — findings (domains, titles, issuers) "
        "are exempt and must stay as they are."
    )


# ---------------------------------------------------------------------------
# brand surfaces
# ---------------------------------------------------------------------------


def test_the_banner_is_ascii() -> None:
    from otacon.utils.theme import banner

    _assert_ascii(_rendered(banner()), "the banner")


def test_the_intro_animation_is_ascii() -> None:
    """Every frame, not just the last: the letters lock one at a time."""
    from otacon._splash import _FRAMES, _frame

    for step in range(_FRAMES):
        _assert_ascii(_frame(step, random.Random(step), MIDNIGHT).plain, f"splash frame {step}")


# ---------------------------------------------------------------------------
# console reporter and engine
# ---------------------------------------------------------------------------


def test_the_console_reporter_is_ascii(report: ScanReport, row: DomainResult) -> None:
    from otacon.reporters import console as rc

    _assert_ascii(_rendered(rc.build_live_table([row], "example.com", 8)), "the live table")
    _assert_ascii(_rendered(rc._verdict_card(report)), "the verdict card")
    _assert_ascii(rc._signals(row), "the signal checklist")

    out = Console(file=io.StringIO(), width=140, theme=_theme())
    rc.render_table(report, out, show_safe=True)
    _assert_ascii(out.file.getvalue(), "the results table")

    agg = Console(file=io.StringIO(), width=140, theme=_theme())
    rc.render_aggregate_summary({"example.com": report}, ["bad..domain"], agg)
    _assert_ascii(agg.file.getvalue(), "the aggregate summary")


def test_the_engines_own_output_is_ascii(row: DomainResult) -> None:
    from otacon.engine import scanner as sc

    _assert_ascii(sc._hijack_warning(), "the NXDOMAIN-hijack warning")
    _assert_ascii(sc._dnsbl_warning(), "the refused-DNSBL warning")
    _assert_ascii(sc._tally([row]), "the running tally")
    _assert_ascii(
        sc._variant_summary([Permutation(domain="a.com", kind=PermutationType.TYPO)]),
        "the variant summary",
    )


# ---------------------------------------------------------------------------
# triage console helpers
# ---------------------------------------------------------------------------


def test_the_tui_widgets_are_ascii(report: ScanReport, row: DomainResult) -> None:
    from otacon.tui import widgets as w

    for name, value in (
        ("tally", w.tally(report)),
        ("distribution", w.distribution(report)),
        ("live_hits", w.live_hits([row])),
        ("scan_tally", w.scan_tally(3, 1)),
        ("logo", w.logo()),
        ("wordmark", w.wordmark()),
        ("risk_bar", w.risk_bar(92)),
        ("signals", w.signals(row)),
    ):
        _assert_ascii(value if isinstance(value, str) else _rendered(value), f"widgets.{name}")
    for level in RiskLevel:
        _assert_ascii(_rendered(w.gutter(level)), f"the {level.value} gutter")
        _assert_ascii(_rendered(w.band_cell(level, True)), f"the {level.value} band label")


def test_absent_data_renders_as_ascii_too(row: DomainResult) -> None:
    """A real scan is mostly rows with no WHOIS answer.

    `format_age(None)` returns U+2014 and leaves degrading to its callers; six
    of the seven forgot, so the triage console printed an em-dash in the AGE
    column of every row whose age was unknown — which no fixture here had,
    because they all carried an age.
    """
    from otacon.net.whois import format_age
    from otacon.triage.dossier import evidence
    from otacon.utils.theme import glyph

    assert glyph(format_age(None)) == "--"
    blank = row.model_copy(update={"age_days": None, "created_at": None})
    _assert_ascii("".join(a + b + c for a, b, c in evidence(blank)), "the dossier with no age")
    _assert_ascii(_rendered(_rendered_age_cell(blank)), "the age cell with no age")


def _rendered_age_cell(r: DomainResult):
    """The AGE cell exactly as the triage console's row builder makes it."""
    from rich.text import Text

    from otacon.net.whois import format_age
    from otacon.utils.theme import glyph

    return Text(glyph(format_age(r.age_days)))


def test_the_verdict_and_dossier_are_ascii(report: ScanReport, row: DomainResult) -> None:
    from otacon.triage.dossier import evidence
    from otacon.triage.notice import build_takedown_notice
    from otacon.triage.verdict import verdict
    from otacon.utils.theme import glyph

    v = verdict(report)
    _assert_ascii(v.headline + v.explanation, "the verdict sentence")
    # marker is deliberately raw so each surface degrades it; check the contract.
    _assert_ascii(glyph(v.marker), "the degraded verdict marker")
    _assert_ascii("".join(a + b + c for a, b, c in evidence(row)), "the dossier evidence")
    # The notice itself keeps its em-dashes on purpose: it is written to a .txt
    # and pasted into a ticket, not drawn on this terminal. Only the console's
    # preview of it is a terminal surface.
    _assert_ascii(glyph(build_takedown_notice(row, "example.com")), "the notice preview")
    assert "—" in build_takedown_notice(row, "example.com"), (
        "the written notice should keep its typography; only the preview degrades"
    )


def test_every_surface_that_degrades_the_verdict_marker_actually_does() -> None:
    """The raw marker is fine; a caller that forgets to degrade it is not."""
    from pathlib import Path

    src = Path(__file__).resolve().parent.parent / "src" / "otacon"
    raw = []
    for path in src.rglob("*.py"):
        if path.name == "verdict.py":
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if ".marker" not in line:
                continue
            if "glyph(" in line or "degrade(" in line:
                continue
            if True:
                raw.append(f"{path.relative_to(src).as_posix()}: {line.strip()}")
    assert not raw, "Verdict.marker rendered without degrading it:\n" + "\n".join(raw)


# ---------------------------------------------------------------------------
# the full Textual application
# ---------------------------------------------------------------------------


def _framework_glyphs() -> frozenset[str]:
    """Textual's own scrollbar glyphs, read from the library rather than guessed.

    Its *borders* follow ``$otacon-border`` and so degrade with everything
    else, but the scrollbar is painted by the framework with no setting to
    change it. Derived here, and asserted not to overlap our own budget, so
    this exclusion can never quietly swallow a glyph of ours.
    """
    import inspect
    import re

    import textual.scrollbar

    source = inspect.getsource(textual.scrollbar)
    found = {c for m in re.finditer(r'"([^"]*)"', source) for c in m.group(1) if ord(c) > 127}
    return frozenset(found)


def test_the_framework_exclusion_cannot_hide_our_own_glyphs() -> None:
    """If Textual ever adopts a glyph we also use, this exclusion stops being safe."""
    from otacon.ui.glyphs import SAFE

    overlap = _framework_glyphs() & SAFE
    assert not overlap, (
        f"Textual now paints {sorted(overlap)}, which is also in our budget — "
        "the scrollbar exclusion in this module would mask a real leak."
    )


def _svg_text(svg: str) -> str:
    """The glyphs a Textual screenshot actually paints, without its chrome.

    The SVG wrapper carries a font stack and a window title of its own, so
    only the <text> content is the application's output.
    """
    import re

    painted = "".join(re.findall(r"<text[^>]*>(.*?)</text>", svg, flags=re.S))
    framework = _framework_glyphs()
    return "".join(c for c in painted if c not in framework)


@pytest.mark.asyncio
async def test_the_triage_console_screens_are_ascii(report: ScanReport) -> None:
    """Overview, results, the help overlay and the OPSEC warning."""
    from otacon.tui.app import OtaconTUI

    app = OtaconTUI(report, palette=MIDNIGHT)
    async with app.run_test(size=(140, 44)) as pilot:
        await pilot.pause()
        _assert_ascii(_svg_text(app.export_screenshot()), "the overview screen")

        await pilot.press("enter")
        await pilot.pause()
        _assert_ascii(_svg_text(app.export_screenshot()), "the results screen")

        await pilot.press("question_mark")
        await pilot.pause()
        _assert_ascii(_svg_text(app.export_screenshot()), "the help overlay")

        await pilot.press("escape")
        await pilot.pause()
        await pilot.press("o")
        await pilot.pause()
        _assert_ascii(_svg_text(app.export_screenshot()), "the OPSEC warning")


@pytest.mark.asyncio
async def test_the_start_screen_is_ascii() -> None:
    """The form, including the collapsed 'Advanced' marker."""
    from otacon.tui.app import OtaconTUI

    app = OtaconTUI(None, palette=MIDNIGHT)
    async with app.run_test(size=(140, 44)) as pilot:
        await pilot.pause()
        _assert_ascii(_svg_text(app.export_screenshot()), "the start screen")
