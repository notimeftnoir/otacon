"""Compatibility shim for scan engine in otacon v2.0."""

from __future__ import annotations

from .engine.scanner import _tally, run_scan

__all__ = ["_tally", "run_scan"]
