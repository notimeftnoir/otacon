# Results Quality & UX Overhaul — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the results table (Option B: risk bar + signal columns), add a defensive-redirect indicator (`⚑`), tighten HTTP scoring, and eliminate Rich markup injection throughout reporters.

**Architecture:** Four production files change in strict dependency order: `models.py` (new field) → `scoring.py` (logic) → `cli.py` / `interactive.py` (callers) → `reporters.py` (presentation). Every step is TDD — failing test first, then minimal implementation.

**Tech Stack:** Python 3.10+, `rich` (`Text`, `Table`, `markup.escape`), `urllib.parse.urlparse`, `pytest`.

---

### Task 1: Add `is_likely_defensive` to `DomainResult`

**Files:**
- Modify: `otacon/models.py`
- Modify: `otacon/tests/test_scoring.py` (new import, new fixture)

- [ ] **Step 1: Write the failing test**

Append to `otacon/tests/test_scoring.py`:

```python
def test_domain_result_is_likely_defensive_defaults_to_false():
    from otacon.models import DomainResult, PermutationType
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)
    assert r.is_likely_defensive is False
```

- [ ] **Step 2: Run to confirm it fails**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest otacon/tests/test_scoring.py::test_domain_result_is_likely_defensive_defaults_to_false -v
```

Expected: `AttributeError: 'DomainResult' object has no attribute 'is_likely_defensive'`

- [ ] **Step 3: Add the field to `DomainResult`**

In `otacon/models.py`, add one line to `DomainResult` after `risk_reasons`:

```python
    risk_reasons: list[str] = Field(default_factory=list)
    is_likely_defensive: bool = False
```

- [ ] **Step 4: Run to confirm it passes**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest otacon/tests/test_scoring.py::test_domain_result_is_likely_defensive_defaults_to_false -v
```

Expected: `PASSED`

- [ ] **Step 5: Commit**

```bash
cd "/Users/Gab/Vscode/otacon project/otacon"
git add models.py tests/test_scoring.py
git commit -m "feat: add is_likely_defensive field to DomainResult"
```

---

### Task 2: Update `scoring.py` — defensive detection + `target` param

**Files:**
- Modify: `otacon/scoring.py`
- Modify: `otacon/tests/test_scoring.py`

- [ ] **Step 1: Write failing tests**

Append to `otacon/tests/test_scoring.py`:

```python
def test_score_sets_is_likely_defensive_when_redirect_matches_target():
    from otacon.models import DomainResult, PermutationType
    from otacon.scoring import score
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        redirects_to="https://www.google.com/",
    )
    result = score(r, target="google.com")
    assert result.is_likely_defensive is True


def test_score_does_not_set_defensive_for_unrelated_redirect():
    from otacon.models import DomainResult, PermutationType
    from otacon.scoring import score
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        redirects_to="https://www.phishing.com/",
    )
    result = score(r, target="google.com")
    assert result.is_likely_defensive is False


def test_score_does_not_set_defensive_when_target_is_empty():
    from otacon.models import DomainResult, PermutationType
    from otacon.scoring import score
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        resolves=True,
        redirects_to="https://www.google.com/",
    )
    result = score(r, target="")
    assert result.is_likely_defensive is False


def test_score_backward_compatible_no_target():
    from otacon.models import DomainResult, PermutationType
    from otacon.scoring import score
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO, resolves=True)
    result = score(r)  # no target — must not raise
    assert result.is_likely_defensive is False
```

- [ ] **Step 2: Run to confirm they fail**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest otacon/tests/test_scoring.py::test_score_sets_is_likely_defensive_when_redirect_matches_target -v
```

Expected: `TypeError: score() takes 1 positional argument but 2 were given` (or similar)

- [ ] **Step 3: Update `score()` and `score_all()` in `scoring.py`**

Replace the entire `scoring.py` with:

```python
"""Risk scoring engine."""
from __future__ import annotations

from .models import DomainResult, PermutationType
from .theme import RiskLevel

_KIND_BASE: dict[PermutationType, int] = {
    PermutationType.HOMOGLYPH: 25,
    PermutationType.TYPO: 18,
    PermutationType.BITSQUAT: 15,
    PermutationType.HYPHEN: 12,
    PermutationType.COMBO: 20,
    PermutationType.TLD_SWAP: 10,
}


def score(result: DomainResult, target: str = "") -> DomainResult:
    """Computes risk_score, risk_level, reasons, and is_likely_defensive. Mutates and returns."""
    if not result.is_registered:
        result.risk_score = 0
        result.risk_level = RiskLevel.SAFE
        result.risk_reasons = []
        return result

    # Defensive-registration detection: redirect points back to the original domain.
    if result.redirects_to and target and target.lower() in result.redirects_to.lower():
        result.is_likely_defensive = True

    points = 0
    reasons: list[str] = []

    base = _KIND_BASE.get(result.kind, 10)
    points += base
    reasons.append(f"technique: {result.kind.value} (+{base})")

    if result.resolves:
        points += 10
        reasons.append("resolves to an IP (+10)")

    if result.has_mx:
        points += 25
        reasons.append("has an MX record — ready for email phishing (+25)")

    if result.has_ssl:
        points += 15
        reasons.append("active SSL certificate (+15)")

    if result.http_status is not None:
        status = result.http_status
        if 200 <= status < 300:
            points += 15
            reasons.append(f"responds HTTP {status} — active site (+15)")
        elif 300 <= status < 400:
            points += 10
            reasons.append(f"responds HTTP {status} — redirect (+10)")
        elif 400 <= status < 500:
            points += 5
            reasons.append(f"responds HTTP {status} — registered, no content (+5)")
        else:
            points += 3
            reasons.append(f"responds HTTP {status} — server error (+3)")

    if result.redirects_to:
        points += 5
        reasons.append("redirects elsewhere (+5)")

    result.risk_score = min(points, 100)
    result.risk_level = RiskLevel.from_score(result.risk_score)
    result.risk_reasons = reasons
    return result


def score_all(results: list[DomainResult], target: str = "") -> list[DomainResult]:
    """Scores the whole list in-place."""
    return [score(r, target) for r in results]
```

- [ ] **Step 4: Run all scoring tests**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest otacon/tests/test_scoring.py -v
```

Expected: all pass

- [ ] **Step 5: Commit**

```bash
cd "/Users/Gab/Vscode/otacon project/otacon"
git add scoring.py tests/test_scoring.py
git commit -m "feat: add target param to score(), detect defensive redirects"
```

---

### Task 3: Tune HTTP status scoring

**Files:**
- Modify: `otacon/tests/test_scoring.py`
- (No code change — already done in Task 2's `scoring.py` rewrite. This task verifies the new deltas.)

- [ ] **Step 1: Write failing tests for new HTTP deltas**

Append to `otacon/tests/test_scoring.py`:

```python
def test_score_http_2xx_gives_fifteen_points():
    from otacon.models import DomainResult, PermutationType
    from otacon.scoring import score
    r = DomainResult(
        domain="googel.com", kind=PermutationType.TYPO,
        resolves=True, http_status=200,
    )
    result = score(r)
    # base=18 (typo) + 10 (resolves) + 15 (HTTP 200) = 43
    assert result.risk_score == 43


def test_score_http_3xx_gives_ten_points():
    from otacon.models import DomainResult, PermutationType
    from otacon.scoring import score
    r = DomainResult(
        domain="googel.com", kind=PermutationType.TYPO,
        resolves=True, http_status=301,
    )
    result = score(r)
    # base=18 + 10 (resolves) + 10 (HTTP 301) = 38
    assert result.risk_score == 38


def test_score_http_4xx_gives_five_points():
    from otacon.models import DomainResult, PermutationType
    from otacon.scoring import score
    r = DomainResult(
        domain="googel.com", kind=PermutationType.TYPO,
        resolves=True, http_status=404,
    )
    result = score(r)
    # base=18 + 10 (resolves) + 5 (HTTP 404) = 33
    assert result.risk_score == 33


def test_score_http_5xx_gives_three_points():
    from otacon.models import DomainResult, PermutationType
    from otacon.scoring import score
    r = DomainResult(
        domain="googel.com", kind=PermutationType.TYPO,
        resolves=True, http_status=500,
    )
    result = score(r)
    # base=18 + 10 (resolves) + 3 (HTTP 500) = 31
    assert result.risk_score == 31
```

- [ ] **Step 2: Run to confirm they pass (implementation already in place)**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest otacon/tests/test_scoring.py -v
```

Expected: all pass (including the four new tests above)

- [ ] **Step 3: Commit**

```bash
cd "/Users/Gab/Vscode/otacon project/otacon"
git add tests/test_scoring.py
git commit -m "test: verify new HTTP scoring deltas (3xx=+10, 5xx=+3)"
```

---

### Task 4: Update callers of `score()` to pass `target`

**Files:**
- Modify: `otacon/cli.py`
- Modify: `otacon/interactive.py`

- [ ] **Step 1: Update `cli._run_scan`**

In `otacon/cli.py`, find the line inside `_run_scan`:

```python
                report.results.append(scoring.score(result))
```

Replace with:

```python
                report.results.append(scoring.score(result, target))
```

- [ ] **Step 2: Update `interactive._scan`**

In `otacon/interactive.py`, find:

```python
                report.results.append(scoring.score(result))
```

Replace with:

```python
                report.results.append(scoring.score(result, domain))
```

- [ ] **Step 3: Fix Rich markup injection in `cli.py`**

`cli.py` passes the raw domain name into Rich markup strings. A domain with `[` or `]` in it (valid in IDN contexts) would break rendering. Import `escape` and guard all user-data insertions.

At the top of `otacon/cli.py`, add to the existing imports:

```python
from rich.markup import escape
```

Then in the `scan()` command body, replace:

```python
    console.print(f"[field]Target:[/field] [value]{domain}[/value]")
    console.print(
        f"[muted]Mode: {'DNS only' if no_http else 'DNS + HTTP/SSL'} · "
        f"concurrency: {concurrency}"
        + (f" · whitelist: {len(exclusions)}" if exclusions else "")
        + "[/muted]"
    )
```

With:

```python
    console.print(f"[field]Target:[/field] [value]{escape(domain)}[/value]")
    console.print(
        f"[muted]Mode: {'DNS only' if no_http else 'DNS + HTTP/SSL'} · "
        f"concurrency: {concurrency}"
        + (f" · whitelist: {len(exclusions)}" if exclusions else "")
        + "[/muted]"
    )
```

- [ ] **Step 4: Run the full test suite**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest otacon/tests/ -v
```

Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
cd "/Users/Gab/Vscode/otacon project/otacon"
git add cli.py interactive.py
git commit -m "fix: pass target to score(), escape domain in Rich markup"
```

---

### Task 5: Add reporter helper functions (TDD)

**Files:**
- Modify: `otacon/reporters.py`
- Modify: `otacon/tests/test_reporters.py`

- [ ] **Step 1: Write failing tests for all helpers**

Append to `otacon/tests/test_reporters.py`:

```python
from otacon.reporters import _check, _domain_cell, _http_cell, _redirect_host, _risk_bar
from otacon.models import DomainResult, PermutationType


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
    assert _redirect_host("https://www.google.com/search?q=1") == "www.google.com"


def test_redirect_host_fallback_for_bare_string():
    assert _redirect_host("not-a-url") == "not-a-url"


def test_redirect_host_empty_string():
    assert _redirect_host("") == ""


def test_domain_cell_contains_domain_and_technique():
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)
    cell = _domain_cell(r)
    assert "googel.com" in cell.plain
    assert "typo" in cell.plain


def test_domain_cell_defensive_shows_flag_and_host():
    r = DomainResult(
        domain="googel.com",
        kind=PermutationType.TYPO,
        redirects_to="https://google.com/",
        is_likely_defensive=True,
    )
    cell = _domain_cell(r)
    assert "⚑" in cell.plain
    assert "google.com" in cell.plain


def test_domain_cell_non_defensive_no_flag():
    r = DomainResult(domain="googel.com", kind=PermutationType.TYPO)
    cell = _domain_cell(r)
    assert "⚑" not in cell.plain
```

- [ ] **Step 2: Run to confirm they fail**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest otacon/tests/test_reporters.py -k "risk_bar or check or http_cell or redirect_host or domain_cell" -v
```

Expected: `ImportError` — helpers don't exist yet

- [ ] **Step 3: Add helpers to `reporters.py`**

**Do NOT remove `_signals()`** — it is still used by `to_markdown()`.

First update the imports at the top of `otacon/reporters.py`. Replace:

```python
from rich.console import Console
from rich.table import Table
```

With:

```python
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.text import Text
```

Then insert the five new helper functions **after** the existing `_signals` function and **before** `render_table`. The existing `_signals` function is unchanged.


def _redirect_host(url: str) -> str:
    """Extracts the hostname from a redirect URL; falls back to the raw value."""
    try:
        host = urlparse(url).netloc
        return host if host else url
    except Exception:
        return url


def _risk_bar(score: int, style: str) -> Text:
    """8-char block bar (████░░░░) + right-justified score, coloured by style."""
    filled = round(score / 100 * 8)
    bar = "█" * filled + "░" * (8 - filled)
    t = Text()
    t.append(bar, style=style)
    t.append(f" {score:>3}", style=style)
    return t


def _check(value: bool) -> Text:
    """Green ✓ when True, dim — when False."""
    return Text("✓", style="ok") if value else Text("—", style="muted")


def _http_cell(status: int | None) -> Text:
    """HTTP status code coloured by range (2xx green, 3xx blue, 4xx dim, 5xx yellow)."""
    if status is None:
        return Text("—", style="muted")
    if 200 <= status < 300:
        style = "ok"
    elif 300 <= status < 400:
        style = "info"
    elif 400 <= status < 500:
        style = "muted"
    else:
        style = "warn"
    return Text(str(status), style=style)


def _domain_cell(result: DomainResult) -> Text:
    """Domain name + dim technique subtitle. ⚑ redirect host appended when defensive."""
    t = Text()
    t.append(result.domain, style="value")
    t.append("\n")
    t.append(result.kind.value, style="muted")
    if result.is_likely_defensive and result.redirects_to:
        t.append("  ⚑ → ", style="warn")
        t.append(_redirect_host(result.redirects_to), style="warn")
    return t
```

- [ ] **Step 4: Run helper tests**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest otacon/tests/test_reporters.py -k "risk_bar or check or http_cell or redirect_host or domain_cell" -v
```

Expected: all pass

- [ ] **Step 5: Commit**

```bash
cd "/Users/Gab/Vscode/otacon project/otacon"
git add reporters.py tests/test_reporters.py
git commit -m "feat: add reporter helper functions with tests"
```

---

### Task 6: Redesign `render_table()` — Option B layout

**Files:**
- Modify: `otacon/reporters.py`
- Modify: `otacon/tests/test_reporters.py`

- [ ] **Step 1: Write failing tests for the new table**

Append to `otacon/tests/test_reporters.py`:

```python
from io import StringIO
from otacon.models import ScanReport
from otacon.theme import RiskLevel
from otacon.reporters import render_table


def _make_console(no_color: bool = True):
    from rich.console import Console
    from otacon.theme import OTACON_THEME
    buf = StringIO()
    return Console(file=buf, no_color=no_color, theme=OTACON_THEME, width=120), buf


def test_render_table_footer_shows_medium_count():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exmaple.com", kind=PermutationType.TYPO,
        resolves=True, risk_score=40, risk_level=RiskLevel.MEDIUM,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    assert "med:" in buf.getvalue()


def test_render_table_shows_defensive_flag():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exampl.com", kind=PermutationType.TYPO,
        resolves=True, is_likely_defensive=True,
        redirects_to="https://example.com/",
        risk_score=28, risk_level=RiskLevel.LOW,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    assert "⚑" in buf.getvalue()


def test_render_table_no_defensive_flag_when_not_defensive():
    report = ScanReport(target="example.com", total_permutations=10)
    r = DomainResult(
        domain="exampl.com", kind=PermutationType.TYPO,
        resolves=True, risk_score=28, risk_level=RiskLevel.LOW,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    assert "⚑" not in buf.getvalue()


def test_render_table_shows_risk_bar_characters():
    report = ScanReport(target="example.com", total_permutations=5)
    r = DomainResult(
        domain="exmaple.com", kind=PermutationType.TYPO,
        resolves=True, risk_score=50, risk_level=RiskLevel.MEDIUM,
    )
    report.results.append(r)
    console, buf = _make_console()
    render_table(report, console)
    output = buf.getvalue()
    assert "█" in output
    assert "░" in output
```

- [ ] **Step 2: Run to confirm they fail**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest otacon/tests/test_reporters.py::test_render_table_footer_shows_medium_count otacon/tests/test_reporters.py::test_render_table_shows_defensive_flag -v
```

Expected: `FAILED` — current table has no `med:` or `⚑`

- [ ] **Step 3: Replace `render_table()` in `reporters.py`**

Replace the entire `render_table` function (keep `to_json` and `to_markdown` unchanged):

```python
def render_table(report: ScanReport, console: Console, show_safe: bool = False) -> None:
    """Renders results as a colored terminal table (Option B layout).

    Columns: Domain+technique | Risk bar | DNS | MX | SSL | HTTP
    Defensive registrations (redirect → original) are flagged with ⚑.
    """
    rows = report.results if show_safe else report.registered

    if not rows:
        console.print("\n[ok]✓ No registered impersonating variants detected.[/ok]")
        console.print(
            f"[muted]  Checked {report.total_permutations} permutations.[/muted]\n"
        )
        return

    rows = sorted(rows, key=lambda r: r.risk_score, reverse=True)

    title = Text()
    title.append("Otacon", style="brand")
    title.append(" · target: ")
    title.append(report.target, style="value")

    table = Table(
        title=title,
        title_justify="left",
        header_style="field",
        expand=True,
        border_style="brand.dim",
        show_lines=False,
    )
    table.add_column("Domain", no_wrap=False, min_width=30)
    table.add_column("Risk", width=14)
    table.add_column("DNS", width=5, justify="center")
    table.add_column("MX", width=5, justify="center")
    table.add_column("SSL", width=5, justify="center")
    table.add_column("HTTP", width=7, justify="center")

    for r in rows:
        table.add_row(
            _domain_cell(r),
            _risk_bar(r.risk_score, r.risk_level.style),
            _check(r.resolves),
            _check(r.has_mx),
            _check(r.has_ssl),
            _http_cell(r.http_status),
        )

    console.print()
    console.print(table)

    threats = report.threats
    crit = sum(1 for r in threats if r.risk_level == RiskLevel.CRITICAL)
    high = sum(1 for r in threats if r.risk_level == RiskLevel.HIGH)
    med = sum(1 for r in threats if r.risk_level == RiskLevel.MEDIUM)
    defensive = sum(1 for r in rows if r.is_likely_defensive)

    footer = Text()
    footer.append(
        f"Permutations: {report.total_permutations} · "
        f"registered: {len(report.registered)} · ",
        style="muted",
    )
    footer.append(f"med: {med}", style="warn")
    footer.append(" · ", style="muted")
    footer.append(f"high: {high}", style="danger")
    footer.append(" · ", style="muted")
    footer.append(f"crit: {crit}", style="critical")
    if defensive:
        footer.append("    ⚑ = likely defensive (redirects to original)", style="warn")
    console.print(footer)
    console.print()
```

- [ ] **Step 4: Run full test suite**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest otacon/tests/ -v
```

Expected: all tests pass

- [ ] **Step 5: Reinstall and smoke test**

```bash
pipx reinstall otacon --quiet
pipx inject otacon "questionary>=2.0.0" --quiet
otacon generate example.com --limit 5
```

Expected: table with Domain/Risk/DNS/MX/SSL/HTTP columns, risk bar visible (`████░░░░`), no traceback.

- [ ] **Step 6: Commit**

```bash
cd "/Users/Gab/Vscode/otacon project/otacon"
git add reporters.py tests/test_reporters.py
git commit -m "feat: redesign results table with risk bar and signal columns (Option B)"
```
