"""Self-contained HTML report generator — Otacon dark palette, no external deps."""

from __future__ import annotations

import html
from datetime import timezone
from urllib.parse import quote

from ._validate import parse_redirect
from .models import DomainResult, ScanReport
from .theme import GLYPH_DEFENSIVE, LOGO_DOTS_BOT, LOGO_DOTS_TOP, RiskLevel
from .whois import format_age

_CSS = """
:root {
    --bg:#0d0d0d; --surface:#151515; --surface2:#1e1e1e;
    --border:#00875f; --brand:#00d7af;
    --ok:#5fd700; --info:#5fafff; --warn:#ffd700;
    --danger:#ff5f5f; --crit-fg:#fff; --crit-bg:#870000;
    --muted:#8a8a8a; --field:#afafaf; --value:#fff;
}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--value);font-family:'Courier New',monospace;
     margin:0;padding:2em;line-height:1.5}
a{color:var(--info)}
.brand{color:var(--brand);font-weight:bold}
.ok{color:var(--ok)}
.info{color:var(--info)}
.warn{color:var(--warn)}
.danger{color:var(--danger)}
.critical{color:var(--crit-fg);background:var(--crit-bg);padding:.1em .3em;border-radius:2px}
.muted{color:var(--muted)}
.field{color:var(--field)}
.value{color:var(--value)}
.logo{color:var(--brand);white-space:pre;font-size:.9em;margin:0}
header{border-bottom:1px solid var(--border);padding-bottom:1em;margin-bottom:1.5em}
.meta{color:var(--muted);font-size:.9em;margin-top:.5em}
.verdict{font-size:1.05em;margin-bottom:1.5em;padding:.6em 1em;
         border-left:3px solid var(--brand);background:var(--surface)}
table{width:100%;border-collapse:collapse;font-size:.9em}
thead th{background:var(--surface2);color:var(--field);padding:.5em .75em;
         text-align:left;border-bottom:1px solid var(--border);white-space:nowrap}
tbody tr{border-bottom:1px solid #1e1e1e}
tbody tr:hover{background:var(--surface)}
td{padding:.45em .75em;vertical-align:top}
.domain-name{color:var(--value);font-weight:bold}
.technique{color:var(--muted);font-size:.85em}
.page-title{color:var(--muted);font-size:.85em;font-style:italic}
.defensive{color:var(--warn)}
.check-yes{color:var(--ok)}
.check-no{color:var(--muted)}
.http-2xx{color:var(--ok)}
.http-3xx{color:var(--info)}
.http-4xx{color:var(--muted)}
.http-5xx{color:var(--warn)}
.age-fresh{color:var(--danger)}
.age-warn{color:var(--warn)}
details summary{cursor:pointer;color:var(--muted);font-size:.8em;margin-top:.3em}
details ul{margin:.3em 0 0 1em;padding:0;font-size:.8em;color:var(--muted)}
footer{margin-top:2em;border-top:1px solid var(--border);
       padding-top:1em;color:var(--muted);font-size:.85em}
.filter-radio{display:none}
.filter-bar{margin:1em 0 .8em;display:flex;gap:.5em;align-items:center;flex-wrap:wrap}
.filter-title{color:var(--field);font-size:.85em;font-weight:bold;margin-right:.4em}
.filter-bar label{
    padding:.25em .65em;
    border:1px solid var(--border);
    border-radius:3px;
    background:var(--surface);
    color:var(--field);
    cursor:pointer;
    font-size:.82em;
    user-select:none;
}
.filter-all:checked ~ .filter-bar .lbl-all,
.filter-threats:checked ~ .filter-bar .lbl-threats,
.filter-crit:checked ~ .filter-bar .lbl-crit,
.filter-high:checked ~ .filter-bar .lbl-high,
.filter-mx:checked ~ .filter-bar .lbl-mx{
    background:var(--brand);
    color:#000;
    font-weight:bold;
    border-color:var(--brand);
}
.filter-threats:checked ~ .table-wrap table tbody tr.row-safe{display:none}
.filter-crit:checked ~ .table-wrap table tbody tr:not(.row-critical){display:none}
.filter-high:checked ~ .table-wrap table tbody tr:not(.row-high){display:none}
.filter-mx:checked ~ .table-wrap table tbody tr:not(.has-mx){display:none}
.sandbox-tag{
    font-size:.75em;
    color:var(--info);
    text-decoration:none;
    padding:.1em .4em;
    border:1px solid #2a4365;
    border-radius:2px;
    margin-left:.5em;
    vertical-align:middle;
}
.sandbox-tag:hover{background:#1a365d;color:#fff}
.defanged-domain{font-family:'Courier New',monospace;color:var(--value)}
.risk-chart {
    width: 100%;
    height: 20px;
    border-radius: 3px;
    overflow: hidden;
    background: var(--surface2);
    margin: .6em 0 .3em;
}
.chart-legend {
    display: flex;
    gap: 1.2em;
    font-size: .8em;
    color: var(--muted);
    margin-bottom: .8em;
    flex-wrap: wrap;
}
.legend-item{display:inline-flex;align-items:center;gap:.4em}
.legend-swatch{width:10px;height:10px;border-radius:2px;display:inline-block}
"""

# Lock the report down: no scripts, fetches, frames, plugins, or form posts.
# Inline <style> requires 'unsafe-inline' for style-src; nothing else is allowed.
_CSP = (
    "default-src 'none'; "
    "style-src 'unsafe-inline'; "
    "img-src data:; "
    "base-uri 'none'; "
    "form-action 'none';"
)

_LEVEL_COLOR: dict[RiskLevel, str] = {
    RiskLevel.SAFE: "#5fd700",
    RiskLevel.LOW: "#5fafff",
    RiskLevel.MEDIUM: "#ffd700",
    RiskLevel.HIGH: "#ff5f5f",
    RiskLevel.CRITICAL: "#ff0000",
}

_LEVEL_CLASS: dict[RiskLevel, str] = {
    RiskLevel.SAFE: "ok",
    RiskLevel.LOW: "info",
    RiskLevel.MEDIUM: "warn",
    RiskLevel.HIGH: "danger",
    RiskLevel.CRITICAL: "critical",
}


def _h(text: str) -> str:
    """HTML-escapes interpolated values — short alias used everywhere in this module."""
    return html.escape(text)


def _check(value: bool) -> str:
    """Renders a boolean as a tick / em-dash cell."""
    return '<span class="check-yes">✓</span>' if value else '<span class="check-no">—</span>'


def _http_cell(status: int | None) -> str:
    """HTTP status cell coloured by 2xx/3xx/4xx/5xx class. Em-dash when None."""
    if status is None:
        return '<span class="check-no">—</span>'
    if 200 <= status < 300:
        cls = "http-2xx"
    elif 300 <= status < 400:
        cls = "http-3xx"
    elif 400 <= status < 500:
        cls = "http-4xx"
    else:
        cls = "http-5xx"
    return f'<span class="{cls}">{status}</span>'


def _age_cell(age_days: int | None) -> str:
    """Age cell with risk-banded styling. Thresholds shared with scoring.py."""
    from .scoring import AGE_FRESH_DAYS, AGE_NEW_DAYS

    if age_days is None:
        return '<span class="check-no">—</span>'
    label = _h(format_age(age_days))
    if age_days < AGE_FRESH_DAYS:
        cls = "age-fresh"  # red — matches scoring threshold and verdict "fresh <7d"
    elif age_days < AGE_NEW_DAYS:
        cls = "age-warn"  # yellow — notable but not critical
    else:
        cls = "value"
    return f'<span class="{cls}">{label}</span>'


def _risk_cell(score: int, level: RiskLevel) -> str:
    """Risk bar (width = score) plus the numeric score, coloured by level."""
    color = _LEVEL_COLOR[level]
    cls = _LEVEL_CLASS[level]
    bar = (
        f'<div style="background:{color};width:{score}%;height:6px;border-radius:3px;'
        f'display:inline-block;vertical-align:middle;min-width:4px;max-width:120px"></div>'
    )
    return f'{bar}<span class="{cls}" style="font-weight:bold;margin-left:.4em">{score}</span>'


def _domain_cell(r: DomainResult) -> str:
    """Domain name + technique, with defanged representation, safe sandbox link, and details."""
    dom = _h(r.domain)
    defanged = _h(r.domain.replace(".", "[.]"))
    href = quote(r.domain, safe=".-")
    sandbox_url = f"https://urlscan.io/search/#{href}"
    sandbox_link = (
        f'<a href="{sandbox_url}" target="_blank" rel="noopener noreferrer" '
        f'class="sandbox-tag" title="Inspect safely on urlscan.io">sandbox ↗</a>'
    )
    parts: list[str] = [
        f'<span class="domain-name" title="{dom}">'
        f'<code class="defanged-domain">{defanged}</code>'
        f" {sandbox_link}"
        f"</span>",
        f'<br><span class="technique">{_h(r.kind.value)}</span>',
    ]
    if r.is_likely_defensive and r.redirects_to:
        parsed = parse_redirect(r.redirects_to)
        host = (parsed[0] if parsed else "") or r.redirects_to
        parts.append(f'<span class="defensive"> {GLYPH_DEFENSIVE} {_h(host)}</span>')
    if r.page_title:
        parts.append(f'<br><span class="page-title">"{_h(r.page_title)}"</span>')
    if r.risk_reasons:
        items = "".join(f"<li>{_h(reason)}</li>" for reason in r.risk_reasons)
        parts.append(f"<details><summary>why?</summary><ul>{items}</ul></details>")
    return "".join(parts)


def _chart_svg(rows: list[DomainResult]) -> str:
    """Renders a compact, inline SVG stacked bar chart showing the risk level distribution."""
    if not rows:
        return ""
    counts = {
        RiskLevel.CRITICAL: sum(1 for r in rows if r.risk_level == RiskLevel.CRITICAL),
        RiskLevel.HIGH: sum(1 for r in rows if r.risk_level == RiskLevel.HIGH),
        RiskLevel.MEDIUM: sum(1 for r in rows if r.risk_level == RiskLevel.MEDIUM),
        RiskLevel.LOW: sum(1 for r in rows if r.risk_level == RiskLevel.LOW),
        RiskLevel.SAFE: sum(1 for r in rows if r.risk_level == RiskLevel.SAFE),
    }
    total = len(rows)
    svg_parts = [
        '<svg viewBox="0 0 600 20" class="risk-chart" role="img" '
        'aria-label="Risk Distribution">'
    ]
    x = 0.0
    for level, color in _LEVEL_COLOR.items():
        cnt = counts[level]
        if cnt > 0:
            width = (cnt / total) * 600.0
            svg_parts.append(
                f'<rect x="{x:.1f}" y="2" width="{width:.1f}" height="16" fill="{color}">'
                f'<title>{level.value}: {cnt} ({cnt * 100 / total:.1f}%)</title></rect>'
            )
            x += width
    svg_parts.append("</svg>")

    legend_items = []
    for level, color in _LEVEL_COLOR.items():
        cnt = counts[level]
        if cnt > 0:
            legend_items.append(
                f'<span class="legend-item">'
                f'<span class="legend-swatch" style="background:{color}"></span> '
                f'{level.value}: {cnt}</span>'
            )
    legend_html = f'<div class="chart-legend">{" ".join(legend_items)}</div>'
    return f'<div class="chart-container">{"".join(svg_parts)}{legend_html}</div>'


def _verdict_html(report: ScanReport) -> str:
    """Top-of-page summary line (clean / N registered + crit/mx/fresh counts)."""
    registered = report.registered
    if not registered:
        return (
            '<span class="ok">✓ clean</span> '
            f'<span class="muted">— {report.total_permutations} permutations checked, '
            f"none registered</span>"
        )
    threats = report.threats
    crit_count = sum(1 for r in threats if r.risk_level == RiskLevel.CRITICAL)
    mx_count = sum(1 for r in registered if r.has_mx)
    from .scoring import AGE_FRESH_DAYS, count_fresh

    fresh_count = count_fresh(registered)
    icon = '<span class="critical">⚠</span>' if crit_count else '<span class="warn">●</span>'
    crit_cls = "critical" if crit_count else "muted"
    mx_cls = "danger" if mx_count else "muted"
    fresh_cls = "critical" if fresh_count else "muted"
    return (
        f'{icon} <span class="value">{len(registered)} registered</span>'
        f' <span class="muted">·</span>'
        f' <span class="{crit_cls}">crit: {crit_count}</span>'
        f' <span class="muted">·</span>'
        f' <span class="{mx_cls}">mx: {mx_count}</span>'
        f' <span class="muted">·</span>'
        f' <span class="{fresh_cls}">fresh &lt;{AGE_FRESH_DAYS}d: {fresh_count}</span>'
    )


def _table_html(rows: list[DomainResult], prefix: str = "f") -> str:
    """Main results table with inline chart and pure-CSS filtering."""
    if not rows:
        return '<p class="muted">No registered variants detected.</p>'

    crit_count = sum(1 for r in rows if r.risk_level == RiskLevel.CRITICAL)
    high_count = sum(1 for r in rows if r.risk_level == RiskLevel.HIGH)
    threats_count = sum(1 for r in rows if r.risk_level != RiskLevel.SAFE)
    mx_count = sum(1 for r in rows if r.has_mx)

    chart = _chart_svg(rows)

    row_html = "\n".join(
        f"<tr class='row-item row-{r.risk_level.value} {'has-mx' if r.has_mx else ''}'>"
        f"<td>{_domain_cell(r)}</td>"
        f"<td>{_risk_cell(r.risk_score, r.risk_level)}</td>"
        f"<td>{_age_cell(r.age_days)}</td>"
        f"<td style='text-align:center'>{_check(r.resolves)}</td>"
        f"<td style='text-align:center'>{_check(r.has_mx)}</td>"
        f"<td style='text-align:center'>{_check(r.has_ssl)}</td>"
        f"<td style='text-align:center'>{_http_cell(r.http_status)}</td>"
        f"</tr>"
        for r in rows
    )

    filter_radios = (
        f'<input type="radio" name="{prefix}-filter" id="{prefix}-all" '
        'class="filter-radio filter-all" checked>'
        f'<input type="radio" name="{prefix}-filter" id="{prefix}-threats" '
        'class="filter-radio filter-threats">'
        f'<input type="radio" name="{prefix}-filter" id="{prefix}-crit" '
        'class="filter-radio filter-crit">'
        f'<input type="radio" name="{prefix}-filter" id="{prefix}-high" '
        'class="filter-radio filter-high">'
        f'<input type="radio" name="{prefix}-filter" id="{prefix}-mx" '
        'class="filter-radio filter-mx">'
    )

    filter_bar = (
        '<div class="filter-bar">'
        '<span class="filter-title">Filter:</span>'
        f'<label for="{prefix}-all" class="lbl-all">All ({len(rows)})</label>'
        f'<label for="{prefix}-threats" class="lbl-threats">Threats ({threats_count})</label>'
        f'<label for="{prefix}-crit" class="lbl-crit">Critical ({crit_count})</label>'
        f'<label for="{prefix}-high" class="lbl-high">High ({high_count})</label>'
        f'<label for="{prefix}-mx" class="lbl-mx">MX ({mx_count})</label>'
        '</div>'
    )

    return (
        f'<div class="report-section">'
        f'{chart}'
        f'{filter_radios}'
        f'{filter_bar}'
        f'<div class="table-wrap"><table>'
        f'<thead><tr>'
        f'<th>Domain</th><th>Risk</th><th>Age</th>'
        f'<th>DNS</th><th>MX</th><th>SSL</th><th>HTTP</th>'
        f'</tr></thead><tbody>{row_html}</tbody></table></div></div>'
    )


def to_html(report: ScanReport) -> str:
    """Returns a complete self-contained HTML document for the scan report."""
    target = _h(report.target)
    started = report.started_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = sorted(report.registered, key=lambda r: r.risk_score, reverse=True)
    threats = report.threats
    registered = report.registered
    med = sum(1 for r in threats if r.risk_level == RiskLevel.MEDIUM)
    high = sum(1 for r in threats if r.risk_level == RiskLevel.HIGH)
    crit = sum(1 for r in threats if r.risk_level == RiskLevel.CRITICAL)
    defensive = sum(1 for r in registered if r.is_likely_defensive)

    sep = ' <span class="muted">·</span> '
    footer_parts = [
        f"Permutations: {report.total_permutations}",
        f"registered: {len(registered)}",
        f'<span class="warn">med: {med}</span>',
        f'<span class="danger">high: {high}</span>',
        f'<span class="critical">crit: {crit}</span>',
    ]
    if defensive:
        footer_parts.append(f'<span class="warn">{GLYPH_DEFENSIVE} {defensive} defensive</span>')

    logo = (
        f" {LOGO_DOTS_TOP}\n"
        '   OTAC<span class="brand">\u041e</span>N'
        '  <span class="muted">[0x041E] homoglyph target</span>\n'
        f' {LOGO_DOTS_BOT}  <span class="muted">domain impersonation detector</span>'
    )
    meta_line = (
        f'<span class="field">Target:</span> <span class="value">{target}</span> &nbsp;'
        f'<span class="field">Date:</span> <span class="value">{started}</span> &nbsp;'
        f'<span class="field">Permutations:</span>'
        f' <span class="value">{report.total_permutations}</span>'
    )
    defensive_note = (
        f'&nbsp;&nbsp;<span class="warn">{GLYPH_DEFENSIVE} = likely defensive'
        " (redirects to original)</span>"
        if defensive
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="{_CSP}">
  <meta name="referrer" content="no-referrer">
  <title>Otacon — {target}</title>
  <style>{_CSS}</style>
</head>
<body>
  <header>
    <pre class="logo">{logo}</pre>
    <div class="meta">{meta_line}</div>
  </header>

  <div class="verdict">{_verdict_html(report)}</div>

  {_table_html(rows)}

  <footer>
    {sep.join(footer_parts)}
    {defensive_note}
  </footer>
</body>
</html>"""


def aggregate_html(reports: dict[str, ScanReport]) -> str:
    """Returns a self-contained HTML document aggregating results for all scanned domains."""
    from datetime import datetime, timezone

    started = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_registered = sum(len(r.registered) for r in reports.values())

    summary_rows = ""
    for domain, report in reports.items():
        registered = report.registered
        crit = sum(1 for r in report.threats if r.risk_level == RiskLevel.CRITICAL)
        high = sum(1 for r in report.threats if r.risk_level == RiskLevel.HIGH)
        med = sum(1 for r in report.threats if r.risk_level == RiskLevel.MEDIUM)
        low = sum(1 for r in report.threats if r.risk_level == RiskLevel.LOW)
        summary_rows += (
            f"<tr>"
            f"<td class='value'><a href='#{_h(domain)}'>{_h(domain)}</a></td>"
            f"<td>{len(registered)}</td>"
            f"<td class='critical'>{crit}</td>"
            f"<td class='danger'>{high}</td>"
            f"<td class='warn'>{med}</td>"
            f"<td class='info'>{low}</td>"
            f"</tr>"
        )

    summary_table = (
        "<h2>Summary</h2>"
        "<table>"
        "<thead><tr>"
        "<th>Domain</th><th>Registered</th>"
        "<th>Critical</th><th>High</th><th>Medium</th><th>Low</th>"
        "</tr></thead>"
        f"<tbody>{summary_rows}</tbody>"
        "</table>"
    )

    domain_sections = ""
    for domain, report in reports.items():
        rows = sorted(report.registered, key=lambda r: r.risk_score, reverse=True)
        safe_dom = _h(domain).replace(".", "-")
        domain_sections += (
            f'<h2 id="{_h(domain)}">{_h(domain)}</h2>'
            f'<div class="verdict">{_verdict_html(report)}</div>'
            f"{_table_html(rows, prefix=f'f-{safe_dom}')}"
        )

    logo = (
        f" {LOGO_DOTS_TOP}\n"
        '   OTAC<span class="brand">\u041e</span>N'
        '  <span class="muted">[0x041E] homoglyph target</span>\n'
        f" {LOGO_DOTS_BOT}"
        '  <span class="muted">domain impersonation detector</span>'
    )
    meta_line = (
        f'<span class="field">Date:</span> <span class="value">{started}</span>'
        f' &nbsp; <span class="field">Domains:</span>'
        f' <span class="value">{len(reports)}</span>'
        f' &nbsp; <span class="field">Total registered:</span>'
        f' <span class="value">{total_registered}</span>'
    )

    h2_style = (
        "color:var(--brand);border-bottom:1px solid var(--border);"
        "padding-bottom:.3em;margin-top:2em"
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="{_CSP}">
  <meta name="referrer" content="no-referrer">
  <title>Otacon — Multi-domain Scan</title>
  <style>{_CSS}
h2{{{h2_style}}}</style>
</head>
<body>
  <header>
    <pre class="logo">{logo}</pre>
    <div class="meta">{meta_line}</div>
  </header>
  {summary_table}
  {domain_sections}
</body>
</html>"""
