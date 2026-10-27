"""Compatibility shim for HTML report generation."""

from __future__ import annotations

from .reporters.html import (
    _CSS,
    aggregate_html,
    to_html,
)

__all__ = [
    "_CSS",
    "aggregate_html",
    "to_html",
]
