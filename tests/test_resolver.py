"""Tests for resolver helpers (page title parsing)."""

from __future__ import annotations

from otacon.resolver import _parse_title


def test_parse_title_basic():
    html = "<html><head><title>Example Domain</title></head></html>"
    assert _parse_title(html) == "Example Domain"


def test_parse_title_with_attrs():
    html = '<title lang="en">Welcome Back</title>'
    assert _parse_title(html) == "Welcome Back"


def test_parse_title_collapses_whitespace():
    html = "<title>  Hello   World  </title>"
    assert _parse_title(html) == "Hello World"


def test_parse_title_truncates_to_80():
    long_title = "A" * 100
    html = f"<title>{long_title}</title>"
    result = _parse_title(html)
    assert result is not None
    assert len(result) == 80


def test_parse_title_missing_returns_none():
    html = "<html><head></head><body>No title here</body></html>"
    assert _parse_title(html) is None


def test_parse_title_empty_tag_returns_none():
    html = "<title></title>"
    assert _parse_title(html) is None


def test_parse_title_case_insensitive():
    html = "<TITLE>Uppercase Tag</TITLE>"
    assert _parse_title(html) == "Uppercase Tag"


def test_parse_title_multiline():
    html = "<title>\n  Phishing Page\n</title>"
    assert _parse_title(html) == "Phishing Page"
