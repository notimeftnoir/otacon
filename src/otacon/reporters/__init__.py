"""Multi-format report generation (Console, JSON, HTML, CSV, Markdown)."""

from __future__ import annotations

from .base import BaseReporter
from .console import (
    _BAR_STYLE,
    _DIST_WIDTH,
    _HIGH_RISK_LEVELS,
    _LEVELS_DESC,
    _POINTS_RE,
    _age_cell,
    _check,
    _distribution,
    _domain_cell,
    _headline,
    _http_cell,
    _redirect_host,
    _results_table,
    _risk_bar,
    _signals,
    _verdict_banner,
    _verdict_card,
    _why,
    build_live_table,
    render_aggregate_summary,
    render_table,
)
from .csv import _FORMULA_TRIGGER_RE, _csv_safe, to_csv
from .html import aggregate_html, to_html
from .json import aggregate_json, to_json
from .markdown import _verdict_banner_md, to_markdown

__all__ = [
    "_BAR_STYLE",
    "_DIST_WIDTH",
    "_FORMULA_TRIGGER_RE",
    "_HIGH_RISK_LEVELS",
    "_LEVELS_DESC",
    "_POINTS_RE",
    "BaseReporter",
    "_age_cell",
    "_check",
    "_csv_safe",
    "_distribution",
    "_domain_cell",
    "_headline",
    "_http_cell",
    "_redirect_host",
    "_results_table",
    "_risk_bar",
    "_signals",
    "_verdict_banner",
    "_verdict_banner_md",
    "_verdict_card",
    "_why",
    "aggregate_html",
    "aggregate_json",
    "build_live_table",
    "render_aggregate_summary",
    "render_table",
    "to_csv",
    "to_html",
    "to_json",
    "to_markdown",
]
