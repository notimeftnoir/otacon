"""Compatibility shim for HTML report generation."""

from __future__ import annotations

from .reporters.html import (
    aggregate_html,
    to_html,
)

__all__ = [
    "aggregate_html",
    "to_html",
]
