"""CLI scan subcommand implementation."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from ... import history
from ..._asyncutils import run_async
from ...core.models import ScanReport
from ...core.types import RiskLevel
from ...engine.scanner import run_scan
from ...reporters import console as reporters
from ...reporters.csv import to_csv
from ...reporters.html import aggregate_html, to_html
from ...reporters.json import aggregate_json, to_json
from ...reporters.markdown import to_markdown
from ...scoring.config import ScoringWeights
from ...utils.validate import (
    is_valid_domain,
    normalize_domain,
    parse_domain_list,
    safe_cli_path,
)
from ..state import _state


def _log_history_failure(console: Console, exc: Exception) -> None:
    """Reports a failed history write once, without derailing the scan."""
    console.print(f"[muted]Could not store this scan in history: {escape(str(exc))}[/muted]")


_OUT, _NET, _FILTER, _CI = "Reports", "Network", "Filtering", "Scoring & CI"


def _load_exclusions(raw: str | None, file: Path | None) -> set[str]:
    out: set[str] = set()
    if raw:
        out.update(normalize_domain(d) for d in raw.split(",") if d.strip())
    if file:
        try:
            content = file.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise typer.BadParameter(f"exclude-file not found: {file}") from exc
        except OSError as exc:
            raise typer.BadParameter(f"cannot read exclude-file: {file}") from exc

        out.update(parse_domain_list(content))
    return out


def _load_domains(raw: list[str], file: Path | None) -> list[str]:
    all_input: list[str] = list(raw)
    if file:
        try:
            content = file.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise typer.BadParameter(f"domains-file not found: {file}") from exc
        except OSError as exc:
            raise typer.BadParameter(f"cannot read domains-file: {file}") from exc
        for line in content.splitlines():
            entry = line.strip()
            if entry and not entry.startswith("#"):
                all_input.append(entry)

    seen: set[str] = set()
    result: list[str] = []
    for raw_domain in all_input:
        normalised = normalize_domain(raw_domain)
        if normalised and normalised not in seen:
            seen.add(normalised)
            result.append(normalised)
    return result


def _load_weights(file: Path | None) -> ScoringWeights:
    if not file:
        return ScoringWeights()
    try:
        content = file.read_text(encoding="utf-8")
        data = json.loads(content)
        return ScoringWeights(data)
    except FileNotFoundError as exc:
        raise typer.BadParameter(f"weights-file not found: {file}") from exc
    except (json.JSONDecodeError, ValueError, TypeError, OSError) as exc:
        raise typer.BadParameter(f"cannot read/parse weights-file: {file}. Error: {exc}") from exc


async def _run_scan(
    target: str,
    concurrency: int,
    check_http: bool,
    exclude: set[str] | None = None,
    quiet: bool = False,
    weights: ScoringWeights | None = None,
    check_whois: bool = True,
    check_dnsbl: bool = True,
    check_ct: bool = True,
    console: Console | None = None,
) -> ScanReport:
    active_console = console or Console()
    res = await run_scan(
        target,
        concurrency=concurrency,
        check_http=check_http,
        console=active_console,
        exclude=exclude,
        weights=weights,
        show_progress=not quiet,
        check_whois=check_whois,
        check_dnsbl=check_dnsbl,
        check_ct=check_ct,
    )
    return res


def _print_next_steps(
    reports: dict[str, ScanReport],
    html_written: bool,
    ci_gated: bool,
    console: Console | None = None,
) -> None:
    active_console = console or Console()
    domain = escape(next(iter(reports)))
    found = any(r.registered for r in reports.values())
    dangerous = any(
        t.risk_level.rank >= RiskLevel.HIGH.rank for r in reports.values() for t in r.threats
    )
    tips: list[tuple[str, str]] = []
    if found and not html_written:
        tips.append(
            (f"otacon scan {domain} --html report.html", "a report to share with your team")
        )
    if dangerous:
        tips.append(("otacon", "triage console: filter, inspect, WHOIS, takedown"))
    if not ci_gated:
        tips.append(
            (f"otacon -q scan {domain} --fail-on high", "automate it in CI or a nightly job")
        )

    grid = Table.grid(padding=(0, 2))
    for cmd, why in tips[:3]:
        grid.add_row("[brand]•[/brand]", f"[bold white]{cmd}[/bold white]", f"[muted]{why}[/muted]")
    active_console.print("[field]Next steps[/field]")
    active_console.print(grid)
    active_console.print()


def execute_scan(
    ctx: typer.Context,
    console: Console,
    domain: list[str] | None,
    domains_file: Path | None,
    json_out: Path | None,
    md_out: Path | None,
    html_out: Path | None,
    csv_out: Path | None,
    no_http: bool,
    no_whois: bool,
    no_dnsbl: bool,
    no_ct: bool,
    concurrency: int,
    show_all: bool,
    exclude: str | None,
    exclude_file: Path | None,
    fail_on: str | None,
    weights_file: Path | None,
) -> None:
    quiet = _state(ctx).quiet
    domains = _load_domains(domain or [], domains_file)

    if not domains:
        console.print("[danger]Error: provide at least one domain to scan.[/danger]")
        raise typer.Exit(1)

    exclusions = _load_exclusions(exclude, exclude_file)
    weights = _load_weights(weights_file)

    all_reports: dict[str, ScanReport] = {}
    scan_errors: list[str] = []

    for d in domains:
        if not is_valid_domain(d):
            console.print(f"[warn]⚠ Skipping invalid domain: {escape(d)}[/warn]")
            scan_errors.append(d)
            continue

        console.print(f"\n[brand]►[/brand] Scanning [bold white]{escape(d)}[/bold white]")
        console.print(
            f"  [muted]{'DNS only' if no_http else 'DNS + HTTP/SSL'}"
            + (" · WHOIS off" if no_whois else " · WHOIS")
            + (" · DNSBL off" if no_dnsbl else " · DNSBL")
            + (" · CT off" if no_ct else " · CT")
            + f" · {concurrency} parallel checks"
            + (f" · whitelist: {len(exclusions)}" if exclusions else "")
            + "[/muted]"
        )

        run_scan_fn = _run_scan
        run_async_fn = run_async
        reporters_mod = reporters

        scan_kwargs: dict[str, Any] = {
            "exclude": exclusions,
            "quiet": quiet,
            "weights": weights,
            "check_whois": not no_whois,
            "check_dnsbl": not no_dnsbl,
            "check_ct": not no_ct,
            "console": console,
        }
        try:
            try:
                coro = run_scan_fn(d, concurrency, check_http=not no_http, **scan_kwargs)
            except TypeError:
                scan_kwargs.pop("console", None)
                try:
                    coro = run_scan_fn(d, concurrency, check_http=not no_http, **scan_kwargs)
                except TypeError:
                    scan_kwargs.pop("check_ct", None)
                    scan_kwargs.pop("check_dnsbl", None)
                    coro = run_scan_fn(d, concurrency, check_http=not no_http, **scan_kwargs)
            report = run_async_fn(coro)
        except KeyboardInterrupt:
            console.print("\n[muted]Interrupted.[/muted]")
            raise typer.Exit(1) from None
        except Exception as exc:
            console.print(f"[warn]⚠ Error scanning {escape(d)}: {escape(str(exc))}[/warn]")
            scan_errors.append(d)
            continue

        try:
            history.save(report)
        except Exception as exc:
            # History is a convenience; never let it cost the operator a scan.
            _log_history_failure(console, exc)

        reporters_mod.render_table(report, console, show_safe=show_all)
        all_reports[d] = report

    if not all_reports:
        raise typer.Exit(1)

    if len(domains) > 1:
        reporters_mod.render_aggregate_summary(all_reports, scan_errors, console)

    multi = len(all_reports) > 1

    def _safe_write(path: Path, content: str, label: str) -> None:
        target_path = safe_cli_path(str(path))
        if not target_path:
            console.print(
                f"[danger]Error: refusing to write to unsafe path: {escape(str(path))}[/danger]"
            )
            return
        try:
            dest = Path(target_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
            console.print(f"[ok]→ {label} saved:[/ok] [url]{escape(target_path)}[/url]")
        except OSError as exc:
            console.print(f"[danger]Error saving {label}: {escape(str(exc))}[/danger]")

    if json_out:
        single_rpt = next(iter(all_reports.values()))
        content = aggregate_json(all_reports) if multi else to_json(single_rpt)
        _safe_write(json_out, content, "JSON")

    if md_out:
        if multi:
            console.print(
                "[muted]--markdown is not supported for multi-domain scans; "
                "use --json or --html.[/muted]"
            )
        else:
            _safe_write(md_out, to_markdown(next(iter(all_reports.values()))), "Markdown")

    if csv_out:
        if multi:
            console.print(
                "[muted]--csv is not supported for multi-domain scans; "
                "use --json or --html.[/muted]"
            )
        else:
            _safe_write(csv_out, to_csv(next(iter(all_reports.values()))), "CSV")

    if html_out:
        single_rpt = next(iter(all_reports.values()))
        content = aggregate_html(all_reports) if multi else to_html(single_rpt)
        _safe_write(html_out, content, "HTML")

    _print_next_steps(
        all_reports,
        html_written=bool(html_out),
        ci_gated=fail_on is not None,
        console=console,
    )

    if quiet:
        sys.stdout.write(
            (aggregate_json(all_reports) if multi else to_json(next(iter(all_reports.values()))))
            + "\n"
        )

    if fail_on is not None:
        threshold = RiskLevel(fail_on)
        if any(
            r.risk_level.rank >= threshold.rank
            for rep in all_reports.values()
            for r in rep.registered
        ):
            raise typer.Exit(2)


__all__ = [
    "_CI",
    "_FILTER",
    "_NET",
    "_OUT",
    "_load_domains",
    "_load_exclusions",
    "_load_weights",
    "_print_next_steps",
    "_run_scan",
    "execute_scan",
]
