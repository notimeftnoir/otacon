# Interactive Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When `otacon` is invoked with no arguments, enter an interactive prompt that asks for a domain, mode (scan/generate via `[*]` arrow menu), and mode-specific options, then runs the tool.

**Architecture:** New module `interactive.py` holds all interactive logic; `cli.py` changes only one line (bare invocation delegates to `interactive.run()`). Async scan logic is duplicated from `cli._run_scan` in `interactive._scan` to avoid circular imports — the two functions use identical building blocks (`Resolver`, `scoring`, `reporters`).

**Tech Stack:** `questionary>=2.0.0` (arrow-key menus), `rich` (already present), `pytest` + `unittest.mock` for tests.

---

### Task 1: Add questionary to dependencies

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add questionary to pyproject.toml dependencies**

In `pyproject.toml`, add `questionary>=2.0.0` to the `[project.dependencies]` list:

```toml
dependencies = [
    "typer>=0.12.0",
    "rich>=13.7.0",
    "httpx>=0.27.0",
    "aiodns>=3.1.0",
    "pydantic>=2.6.0",
    "questionary>=2.0.0",
]
```

- [ ] **Step 2: Install into the dev venv**

```bash
"/Users/Gab/Vscode/otacon project/.venv/bin/pip" install "questionary>=2.0.0"
```

Expected: `Successfully installed questionary-X.Y.Z`

- [ ] **Step 3: Commit**

```bash
cd "/Users/Gab/Vscode/otacon project/otacon"
git add pyproject.toml
git commit -m "feat: add questionary dependency for interactive mode"
```

---

### Task 2: Create interactive.py — validators

**Files:**
- Create: `tests/test_interactive.py`
- Create: `interactive.py`

- [ ] **Step 1: Write failing validator tests**

Create `tests/test_interactive.py`:

```python
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
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest tests/test_interactive.py -v
```

Expected: `ImportError: cannot import name '_validate_domain' from 'otacon.interactive'`

- [ ] **Step 3: Create interactive.py with validators**

Create `interactive.py` inside the `otacon/` package directory:

```python
"""Interactive entry point — prompts for domain and options when otacon is run bare."""
from __future__ import annotations

import asyncio

import questionary
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from . import permutations, reporters, scoring
from .models import ScanReport
from .resolver import Resolver

_POINTER = "[*]"


def _validate_domain(text: str) -> bool | str:
    if not text.strip():
        return "Domain cannot be empty"
    return True


def _validate_limit(text: str) -> bool | str:
    try:
        if int(text) < 0:
            return "Enter 0 or greater"
        return True
    except ValueError:
        return "Enter a number (0 = all)"


def run(console: Console) -> None:
    """Called by cli._main when otacon is invoked with no subcommand."""
    pass


def _interactive_scan(domain: str, console: Console) -> None:
    pass


def _interactive_generate(domain: str, console: Console) -> None:
    pass


async def _scan(domain: str, concurrency: int, check_http: bool, console: Console) -> ScanReport:
    pass  # type: ignore[return-value]
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest tests/test_interactive.py -v
```

Expected: `8 passed`

- [ ] **Step 5: Commit**

```bash
cd "/Users/Gab/Vscode/otacon project/otacon"
git add interactive.py tests/test_interactive.py
git commit -m "feat: add interactive module with input validators"
```

---

### Task 3: Implement run() — domain input and mode selection

**Files:**
- Modify: `tests/test_interactive.py`
- Modify: `interactive.py`

- [ ] **Step 1: Write failing tests for run() flow**

Append to `tests/test_interactive.py`:

```python
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
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest tests/test_interactive.py::test_run_routes_to_scan tests/test_interactive.py::test_run_routes_to_generate -v
```

Expected: `FAILED` (run() is `pass`)

- [ ] **Step 3: Implement run()**

Replace the `run()` stub in `interactive.py`:

```python
def run(console: Console) -> None:
    """Called by cli._main when otacon is invoked with no subcommand."""
    domain = questionary.text("Domain:", validate=_validate_domain).ask()
    if domain is None:
        return
    domain = domain.strip()

    mode = questionary.select(
        "Mode:",
        choices=[
            questionary.Choice(
                "scan    — DNS + HTTP, detects registered variants", value="scan"
            ),
            questionary.Choice(
                "generate — offline variants, no network", value="generate"
            ),
        ],
        pointer=_POINTER,
    ).ask()
    if mode is None:
        return

    if mode == "scan":
        _interactive_scan(domain, console)
    else:
        _interactive_generate(domain, console)
```

- [ ] **Step 4: Run all interactive tests**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest tests/test_interactive.py -v
```

Expected: `12 passed`

- [ ] **Step 5: Commit**

```bash
cd "/Users/Gab/Vscode/otacon project/otacon"
git add interactive.py tests/test_interactive.py
git commit -m "feat: implement run() with domain input and mode selection"
```

---

### Task 4: Implement generate branch

**Files:**
- Modify: `tests/test_interactive.py`
- Modify: `interactive.py`

- [ ] **Step 1: Write failing test for generate branch**

Append to `tests/test_interactive.py`:

```python
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
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest tests/test_interactive.py::test_interactive_generate_prints_variants -v
```

Expected: `FAILED` (stub returns None)

- [ ] **Step 3: Implement _interactive_generate()**

Replace the `_interactive_generate` stub in `interactive.py`:

```python
def _interactive_generate(domain: str, console: Console) -> None:
    limit_str = questionary.text(
        "Result limit (0 = all):", default="0", validate=_validate_limit
    ).ask()
    if limit_str is None:
        return

    limit = int(limit_str)
    perms = permutations.generate(domain)
    shown = perms[:limit] if limit > 0 else perms

    console.print(
        f"[field]Generated[/field] [value]{len(perms)}[/value] "
        f"[field]variants for[/field] [value]{domain}[/value]\n"
    )
    for p in shown:
        console.print(
            f"  [value]{p.domain:<40}[/value] [muted]{p.kind.value:<12} {p.note}[/muted]"
        )
    if limit and len(perms) > limit:
        console.print(f"\n[muted]... and {len(perms) - limit} more[/muted]")
```

- [ ] **Step 4: Run all interactive tests**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest tests/test_interactive.py -v
```

Expected: `15 passed`

- [ ] **Step 5: Commit**

```bash
cd "/Users/Gab/Vscode/otacon project/otacon"
git add interactive.py tests/test_interactive.py
git commit -m "feat: implement generate branch in interactive mode"
```

---

### Task 5: Implement scan branch and _scan()

**Files:**
- Modify: `tests/test_interactive.py`
- Modify: `interactive.py`

- [ ] **Step 1: Write failing tests for scan branch**

Append to `tests/test_interactive.py`:

```python
from unittest.mock import AsyncMock


def test_interactive_scan_full_calls_render_table():
    """Full scan (HTTP) must call reporters.render_table with correct params."""
    from otacon.models import ScanReport

    mock_report = ScanReport(target="example.com", total_permutations=0)

    with patch("otacon.interactive.questionary") as mock_q, \
         patch("otacon.interactive._scan", new_callable=AsyncMock) as mock_scan, \
         patch("otacon.interactive.reporters") as mock_reporters:

        mock_q.select.return_value.ask.return_value = "full"
        mock_q.confirm.return_value.ask.return_value = False
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

        mock_q.select.return_value.ask.return_value = "dns"
        mock_q.confirm.return_value.ask.return_value = False
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

        mock_q.select.return_value.ask.return_value = "full"
        mock_q.confirm.return_value.ask.return_value = None

        console = MagicMock()
        from otacon.interactive import _interactive_scan
        _interactive_scan("example.com", console)
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest tests/test_interactive.py::test_interactive_scan_full_calls_render_table -v
```

Expected: `FAILED` (stubs return None)

- [ ] **Step 3: Implement _interactive_scan() and _scan()**

Replace both stubs in `interactive.py`:

```python
def _interactive_scan(domain: str, console: Console) -> None:
    network = questionary.select(
        "Network:",
        choices=[
            questionary.Choice("DNS + HTTP  (full, slower)", value="full"),
            questionary.Choice("DNS only    (fast)", value="dns"),
        ],
        pointer=_POINTER,
    ).ask()
    if network is None:
        return

    show_all = questionary.confirm("Show unregistered variants?", default=False).ask()
    if show_all is None:
        return

    check_http = network == "full"
    report = asyncio.run(_scan(domain, concurrency=50, check_http=check_http, console=console))
    reporters.render_table(report, console, show_safe=show_all)


async def _scan(domain: str, concurrency: int, check_http: bool, console: Console) -> ScanReport:
    perms = permutations.generate(domain)
    report = ScanReport(target=domain, total_permutations=len(perms))
    if not perms:
        return report

    with Progress(
        SpinnerColumn(style="brand"),
        TextColumn("[field]{task.description}"),
        BarColumn(complete_style="brand", finished_style="ok"),
        TextColumn("[muted]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Checking variants", total=len(perms))
        async with Resolver(concurrency=concurrency, check_http=check_http) as resolver:
            coros = [resolver.check_one(p) for p in perms]
            for coro in asyncio.as_completed(coros):
                result = await coro
                report.results.append(scoring.score(result))
                progress.advance(task)

    return report
```

- [ ] **Step 4: Run all interactive tests**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest tests/test_interactive.py -v
```

Expected: `19 passed`

- [ ] **Step 5: Run full test suite**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest tests/ -v
```

Expected: all tests pass (previously 20, now 39)

- [ ] **Step 6: Commit**

```bash
cd "/Users/Gab/Vscode/otacon project/otacon"
git add interactive.py tests/test_interactive.py
git commit -m "feat: implement scan branch and async _scan() in interactive mode"
```

---

### Task 6: Wire interactive mode into cli.py

**Files:**
- Modify: `tests/test_cli.py`
- Modify: `cli.py`

- [ ] **Step 1: Write failing test**

Append to `tests/test_cli.py`:

```python
def test_bare_invocation_calls_interactive(monkeypatch) -> None:
    """Running otacon with no subcommand must call interactive.run()."""
    called = {}

    def fake_interactive_run(console):
        called["ran"] = True

    monkeypatch.setattr("otacon.interactive.run", fake_interactive_run)

    from typer.testing import CliRunner
    from otacon.cli import app

    runner = CliRunner()
    result = runner.invoke(app, [])
    assert called.get("ran") is True
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest tests/test_cli.py::test_bare_invocation_calls_interactive -v
```

Expected: `FAILED` — `called` is empty (current code shows help text)

- [ ] **Step 3: Modify _main() in cli.py**

Replace the `_main` callback body in `cli.py`. Find:

```python
@app.callback(invoke_without_command=True)
def _main(ctx: typer.Context) -> None:
    """Shows the banner before any command, and help when run bare."""
    _banner()
    # No subcommand given (bare `otacon`) → print help and exit cleanly.
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit()
```

Replace with:

```python
@app.callback(invoke_without_command=True)
def _main(ctx: typer.Context) -> None:
    """Shows the banner before any command; enters interactive mode when run bare."""
    _banner()
    if ctx.invoked_subcommand is None:
        from .interactive import run as _interactive_run
        _interactive_run(console)
        raise typer.Exit()
```

- [ ] **Step 4: Run full test suite**

```bash
cd "/Users/Gab/Vscode/otacon project"
.venv/bin/python -m pytest tests/ -v
```

Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
cd "/Users/Gab/Vscode/otacon project/otacon"
git add cli.py tests/test_cli.py
git commit -m "feat: wire interactive mode into cli bare invocation"
```

---

### Task 7: Reinstall globally and smoke test

**Files:** none (installation step)

- [ ] **Step 1: Reinstall via pipx**

```bash
pipx reinstall otacon
```

Expected: `reinstalled otacon X.Y.Z`

- [ ] **Step 2: Smoke test — bare invocation triggers interactive mode**

```bash
otacon
```

Expected: banner → "Domain:" prompt → arrow menu with `[*]` pointer

- [ ] **Step 3: Smoke test — existing subcommands still work**

```bash
otacon generate example.com --limit 5
```

Expected: same output as before (banner + table, no interactive prompt)
