"""Otacon — domain impersonation detector.

A toolkit for detecting typosquatting, homoglyph attacks and combosquatting.
"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("otacon")
except PackageNotFoundError:
    __version__ = "dev"
