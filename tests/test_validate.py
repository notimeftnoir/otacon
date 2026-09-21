"""Targeted coverage for _validate.safe_relative_path rejection branches.

The function is the single gatekeeper for every file written by the CLI and
the interactive shell — it must refuse anything that could escape the CWD,
overwrite an absolute path, or trip a Windows reserved-name handler.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from otacon._validate import (
    first_safe_ip,
    is_valid_domain,
    normalize_domain,
    parse_domain_list,
    safe_relative_path,
)


def test_accepts_simple_relative_name(tmp_path: Path) -> None:
    result = safe_relative_path("report.json", base=str(tmp_path))
    assert result is not None
    assert Path(result) == (tmp_path / "report.json").resolve()


def test_rejects_empty_string() -> None:
    assert safe_relative_path("") is None


def test_rejects_nul_byte() -> None:
    assert safe_relative_path("evil\x00.json") is None


def test_rejects_absolute_path(tmp_path: Path) -> None:
    target = tmp_path / "abs.json"
    assert safe_relative_path(str(target), base=str(tmp_path)) is None


def test_rejects_windows_drive_letter(tmp_path: Path) -> None:
    assert safe_relative_path("C:\\evil.json", base=str(tmp_path)) is None


@pytest.mark.parametrize(
    "name",
    ["CON", "PRN", "AUX", "NUL", "COM1", "LPT9", "con.txt", "lpt3.log"],
)
def test_rejects_windows_reserved_names(name: str, tmp_path: Path) -> None:
    assert safe_relative_path(name, base=str(tmp_path)) is None


def test_rejects_parent_dir_escape(tmp_path: Path) -> None:
    # ../outside resolves above base, so relative_to() raises ValueError.
    nested = tmp_path / "nested"
    nested.mkdir()
    assert safe_relative_path("../outside.json", base=str(nested)) is None


def test_rejects_deep_parent_escape(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert safe_relative_path("../../../etc/passwd", base=str(nested)) is None


def test_accepts_subdirectory(tmp_path: Path) -> None:
    sub = tmp_path / "out"
    sub.mkdir()
    result = safe_relative_path(os.path.join("out", "file.json"), base=str(tmp_path))
    assert result is not None
    assert Path(result).parent == sub.resolve()


# ---------------------------------------------------------------------------
# is_valid_domain — every rejection path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "domain",
    [
        "example.com",
        "sub.example.com",
        "xn--exmple-4ve.com",
        "a.b.c.d.example.com",
        "EXAMPLE.com",
        "1stbank.co.uk",
    ],
)
def test_is_valid_domain_accepts(domain: str) -> None:
    assert is_valid_domain(domain) is True


@pytest.mark.parametrize(
    "domain",
    [
        "",  # empty
        "a" * 254,  # > 253 chars
        "exa mple.com",  # whitespace
        "example.com\x00",  # NUL
        "example.com/path",  # path separator
        "user@example.com",  # @ sign
        "example.com:80",  # port-like ":"
        "1.2.3.4",  # bare IPv4
        "::1",  # bare IPv6
        "singlelabel",  # only one label
        "-bad.com",  # leading dash
        "bad-.com",  # trailing dash
        "ok." + "x" * 64 + ".com",  # label > 63 chars
    ],
)
def test_is_valid_domain_rejects(domain: str) -> None:
    assert is_valid_domain(domain) is False


def test_is_valid_domain_rejects_backslash() -> None:
    """Backslash is a Windows path separator and must never reach DNS."""
    assert is_valid_domain("evil\\example.com") is False


# ---------------------------------------------------------------------------
# normalize_domain — the single canonicalisation every entry point shares.
# ---------------------------------------------------------------------------


def test_normalize_domain_full_chain() -> None:
    """Default: trims, lowercases, drops a leading 'www.' and a trailing dot."""
    assert normalize_domain("  WWW.Example.COM.  ") == "example.com"


def test_normalize_domain_strips_www_from_whitelist_entries() -> None:
    """Whitelist entries lose 'www.' like every other input.

    They are only ever compared against permutation output, which never carries a
    'www.' prefix — keeping it would make such an entry match nothing.
    """
    assert normalize_domain("WWW.Example.com.") == "example.com"


# ---------------------------------------------------------------------------
# parse_domain_list — the single reader for --exclude-file and whitelist.txt.
# ---------------------------------------------------------------------------


def test_parse_domain_list_drops_comments_and_blanks() -> None:
    content = "# a comment\n\nexample.com\n   \n  # indented comment\nexample.net\n"
    assert parse_domain_list(content) == {"example.com", "example.net"}


def test_parse_domain_list_normalises_every_entry() -> None:
    """Casing, padding, 'www.' and a trailing root dot all collapse to one form."""
    assert parse_domain_list("  WWW.Example.COM.  \nexample.com\n") == {"example.com"}


def test_parse_domain_list_tolerates_crlf() -> None:
    """A file saved on Windows must read back as the same set it was written from.

    Without this, the defensive-registration writer appends an entry it already
    wrote on the previous run, growing whitelist.txt on every scan.
    """
    assert parse_domain_list("example.com\r\nexample.net\r\n") == {"example.com", "example.net"}


def test_parse_domain_list_empty_content() -> None:
    assert parse_domain_list("") == set()


# ---------------------------------------------------------------------------
# first_safe_ip — used by the Resolver's own HTTP/TLS probing of
# attacker-registered lookalikes.
# ---------------------------------------------------------------------------


def test_first_safe_ip_returns_first_public_address() -> None:
    assert first_safe_ip(["1.1.1.1", "8.8.8.8"]) == "1.1.1.1"


def test_first_safe_ip_rejects_loopback() -> None:
    assert first_safe_ip(["127.0.0.1"]) is None


def test_first_safe_ip_rejects_cloud_metadata_link_local() -> None:
    assert first_safe_ip(["169.254.169.254"]) is None


def test_first_safe_ip_rejects_private_rfc1918() -> None:
    assert first_safe_ip(["10.0.0.5"]) is None


def test_first_safe_ip_mixed_public_and_private_poisons_batch() -> None:
    """A domain answering with both a public and an internal IP is itself a
    rebinding-style red flag — reject the whole batch, don't just pick the
    public one."""
    assert first_safe_ip(["8.8.8.8", "10.0.0.5"]) is None


def test_first_safe_ip_skips_unparseable_entries() -> None:
    assert first_safe_ip(["not-an-ip", "8.8.8.8"]) == "8.8.8.8"


def test_first_safe_ip_empty_list_returns_none() -> None:
    assert first_safe_ip([]) is None


def test_first_safe_ip_accepts_public_ipv6() -> None:
    assert first_safe_ip(["2606:4700:4700::1111"]) == "2606:4700:4700::1111"


def test_first_safe_ip_rejects_ipv6_loopback() -> None:
    assert first_safe_ip(["::1"]) is None


def test_first_safe_ip_rejects_ipv4_mapped_link_local() -> None:
    """IPv4-mapped IPv6 (::ffff:x.x.x.x) must not bypass the cloud-metadata guard —
    a resolver or attacker could hand back this form instead of bare IPv4."""
    assert first_safe_ip(["::ffff:169.254.169.254"]) is None


def test_first_safe_ip_rejects_nat64_embedded_link_local() -> None:
    """NAT64 well-known prefix (64:ff9b::/96) embedding a link-local IPv4 address
    must also be rejected — same bypass class as the IPv4-mapped form above."""
    assert first_safe_ip(["64:ff9b::169.254.169.254"]) is None


def test_parse_redirect_returns_none_for_a_malformed_ipv6_authority() -> None:
    """urlparse raises ValueError on 'http://[evil' rather than degrading.

    A Location header is verbatim attacker output, so the unguarded call was a
    remote crash: one hostile lookalike aborted scoring for the whole target.
    """
    from otacon._validate import parse_redirect

    assert parse_redirect("http://[evil") is None
    assert parse_redirect("http://[::1") is None


def test_parse_redirect_normalises_host_and_reports_scheme() -> None:
    from otacon._validate import parse_redirect

    assert parse_redirect("https://EXAMPLE.com./path") == ("example.com", "https")
    # A relative Location has neither host nor scheme — how same-origin is spotted.
    assert parse_redirect("/login") == ("", "")
