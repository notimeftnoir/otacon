"""Multi-format report generation (Console, JSON, HTML, CSV, Markdown)."""

from __future__ import annotations

from .console import (
    _age_cell,
    _check,
    _distribution,
    _domain_cell,
    _headline,
    _http_cell,
    _redirect_host,
    _risk_bar,
    _verdict_banner,
    _verdict_card,
    _why,
    build_live_table,
    render_aggregate_summary,
    render_table,
)
from .csv import to_csv
from .json import aggregate_json, to_json
from .markdown import _verdict_banner_md, to_markdown

__all__ = [
    "_age_cell",
    "_check",
    "_distribution",
    "_domain_cell",
    "_headline",
    "_http_cell",
    "_redirect_host",
    "_risk_bar",
    "_verdict_banner",
    "_verdict_banner_md",
    "_verdict_card",
    "_why",
    "aggregate_json",
    "build_live_table",
    "render_aggregate_summary",
    "render_table",
    "to_csv",
    "to_json",
    "to_markdown",
]
