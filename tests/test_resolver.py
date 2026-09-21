"""Tests for resolver helpers (page title parsing, WHOIS dedup)."""

from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from otacon.models import Permutation, PermutationType
from otacon.resolver import _MAX_BODY_BYTES, Resolver, _parse_title


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


def test_parse_title_unescapes_html_entities():
    assert _parse_title("<title>Tom &amp; Jerry</title>") == "Tom & Jerry"
    assert _parse_title("<title>Page &#8211; Subtitle</title>") == "Page – Subtitle"  # noqa: RUF001 — en-dash is the actual character &#8211; decodes to


# ---------------------------------------------------------------------------
# _strip_unsafe_chars — control/format/line-separator chars stripped before a
# hostile page title or redirect Location is ever echoed to a terminal/report.
# ---------------------------------------------------------------------------


def test_strip_unsafe_chars_removes_c0_and_c1_control_codes():
    from otacon.resolver import _strip_unsafe_chars

    assert _strip_unsafe_chars("evil\x1b[31mred\x1b[0m") == "evil[31mred[0m"
    assert _strip_unsafe_chars("evil\x9b31mred") == "evil31mred"


def test_strip_unsafe_chars_removes_format_and_separator_chars():
    from otacon.resolver import _strip_unsafe_chars

    assert _strip_unsafe_chars("safe\u202etext") == "safetext"
    assert _strip_unsafe_chars("line1\u2028line2\u2029") == "line1line2"


def test_strip_unsafe_chars_leaves_normal_text_untouched():
    from otacon.resolver import _strip_unsafe_chars

    assert _strip_unsafe_chars("Ordinary Title – 100% safe") == "Ordinary Title – 100% safe"  # noqa: RUF001 — en-dash is deliberate, not a stray control char


def test_parse_title_strips_unsafe_chars_from_extracted_title():
    html = "<title>evil\x1b[31mtitle</title>"
    assert _parse_title(html) == "evil[31mtitle"


# ---------------------------------------------------------------------------
# Body cap — a hostile server can't OOM the scanner with a giant/bomb body
# ---------------------------------------------------------------------------


class _FakeStreamResp:
    """Minimal stand-in for httpx.Response.aiter_bytes — counts bytes produced."""

    def __init__(self, total: int, chunk_size: int = 8192) -> None:
        self._total = total
        self._chunk_size = chunk_size
        self.produced = 0

    async def aiter_bytes(self):
        while self.produced < self._total:
            n = min(self._chunk_size, self._total - self.produced)
            self.produced += n
            yield b"a" * n


@pytest.mark.asyncio
async def test_read_capped_stops_at_limit():
    # 50 MB "body" — _read_capped must return <= cap and stop pulling early
    # (never materialising the whole thing, as with a decompression bomb).
    resp = _FakeStreamResp(50 * 1024 * 1024)
    text = await Resolver._read_capped(resp)
    assert len(text.encode("utf-8")) <= _MAX_BODY_BYTES
    # Generation halted shortly after the cap, not after the full 50 MB.
    assert resp.produced < _MAX_BODY_BYTES + resp._chunk_size


@pytest.mark.asyncio
async def test_read_capped_small_body_intact():
    resp = _FakeStreamResp(100)
    text = await Resolver._read_capped(resp)
    assert text == "a" * 100


# ---------------------------------------------------------------------------
# WHOIS deduplication — two concurrent check_one calls → one fetch_domain_age
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_whois_cache_deduplicates():
    call_count = 0

    async def mock_fetch(domain: str):
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0)  # yield so the second coroutine can reach _cached_whois
        return None, None

    perm = Permutation(domain="paypal.com", kind=PermutationType.TYPO)

    with patch("otacon.resolver.fetch_domain_age", side_effect=mock_fetch):
        async with Resolver() as r:
            with patch.object(r, "_resolve_a", new_callable=AsyncMock, return_value=["1.2.3.4"]):
                with patch.object(r, "_resolve_mx", new_callable=AsyncMock, return_value=[]):
                    ssl_ret = (False, None, None, None)
                    ssl_patch = patch.object(
                        r, "_check_ssl", new_callable=AsyncMock, return_value=ssl_ret
                    )
                    with ssl_patch:
                        probe = AsyncMock(return_value=(None, None, None, None))
                        with patch.object(r, "_probe_http", new=probe):
                            with patch.object(
                                r,
                                "_probe_wildcard",
                                new_callable=AsyncMock,
                                return_value=frozenset(),
                            ):
                                await asyncio.gather(r.check_one(perm), r.check_one(perm))

    assert call_count == 1


# ---------------------------------------------------------------------------
# AAAA support — IPv6-only domains must still count as resolving
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_a_merges_a_and_aaaa():
    r = Resolver()

    async def fake_query(domain: str, rtype: str):
        return ["1.2.3.4"] if rtype == "A" else ["2001:db8::1"]

    with patch.object(r, "_query_ips", side_effect=fake_query):
        ips = await r._resolve_a("example.com")
    assert ips == ["1.2.3.4", "2001:db8::1"]


@pytest.mark.asyncio
async def test_resolve_a_ipv6_only():
    r = Resolver()

    async def fake_query(domain: str, rtype: str):
        return [] if rtype == "A" else ["2001:db8::1"]

    with patch.object(r, "_query_ips", side_effect=fake_query):
        ips = await r._resolve_a("example.com")
    assert ips == ["2001:db8::1"]


# ---------------------------------------------------------------------------
# NXDOMAIN-hijack canary — hijacked answers are discarded, real ones kept
# ---------------------------------------------------------------------------


def _patch_network(r: Resolver, *, resolve_ips: list[str]):
    """Patches all network calls on *r*; returns the contextmanager stack."""
    from contextlib import ExitStack

    stack = ExitStack()
    stack.enter_context(
        patch.object(r, "_resolve_a", new_callable=AsyncMock, return_value=resolve_ips)
    )
    stack.enter_context(patch.object(r, "_resolve_mx", new_callable=AsyncMock, return_value=[]))
    stack.enter_context(
        patch.object(
            r,
            "_check_ssl",
            new_callable=AsyncMock,
            return_value=(False, None, None, None),
        )
    )
    stack.enter_context(
        patch.object(r, "_probe_http", new=AsyncMock(return_value=(None, None, None, None)))
    )
    stack.enter_context(
        patch("otacon.resolver.fetch_domain_age", new=AsyncMock(return_value=(None, None)))
    )
    return stack


@pytest.mark.asyncio
async def test_hijacked_answer_discarded():
    perm = Permutation(domain="paypa1.com", kind=PermutationType.HOMOGLYPH)
    async with Resolver() as r:
        with _patch_network(r, resolve_ips=["198.51.100.7"]):
            # Canary resolves to the same IP — resolver hijacks NXDOMAIN.
            with patch.object(
                r,
                "_probe_wildcard",
                new_callable=AsyncMock,
                return_value=frozenset({"198.51.100.7"}),
            ):
                result = await r.check_one(perm)
        assert result.resolves is False
        assert result.ip_addresses == []
        assert result.is_registered is False


@pytest.mark.asyncio
async def test_genuine_answer_kept_despite_hijack():
    perm = Permutation(domain="paypa1.com", kind=PermutationType.HOMOGLYPH)
    async with Resolver() as r:
        with _patch_network(r, resolve_ips=["203.0.113.9"]):
            with patch.object(
                r,
                "_probe_wildcard",
                new_callable=AsyncMock,
                return_value=frozenset({"198.51.100.7"}),
            ):
                result = await r.check_one(perm)
        assert result.resolves is True
        assert result.ip_addresses == ["203.0.113.9"]


@pytest.mark.asyncio
async def test_no_hijack_keeps_answers():
    perm = Permutation(domain="paypa1.com", kind=PermutationType.HOMOGLYPH)
    async with Resolver() as r:
        with _patch_network(r, resolve_ips=["203.0.113.9"]):
            with patch.object(
                r,
                "_probe_wildcard",
                new_callable=AsyncMock,
                return_value=frozenset(),
            ):
                result = await r.check_one(perm)
        assert result.resolves is True
        assert r.dns_hijack_detected is False


@pytest.mark.asyncio
async def test_dns_hijack_detected_property():
    async with Resolver() as r:
        with patch.object(
            r,
            "_probe_wildcard",
            new_callable=AsyncMock,
            return_value=frozenset({"198.51.100.7"}),
        ):
            assert r.dns_hijack_detected is False  # canary not fired yet
            await r._wildcard_ips()
            assert r.dns_hijack_detected is True


# ---------------------------------------------------------------------------
# _inspect_cert — the TLS-cert reader feeds scoring; every branch must be safe
#
# The probe handshakes with CERT_NONE (hostile lookalikes have broken certs by
# design) and CPython returns an EMPTY dict from text-form getpeercert() for
# unvalidated certs — so the reader must use the DER form. These tests build
# real DER certificates and fake an SSLObject with exact CERT_NONE semantics.
# ---------------------------------------------------------------------------


def _make_der_cert(
    issuer_cn: str | None = "Test CA",
    not_before: datetime | None = None,
    san: tuple[str, ...] | None = ("lookalike.example.com",),
) -> bytes:
    """Builds a real self-signed certificate and returns its DER bytes."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    nb = not_before or (datetime.now(timezone.utc) - timedelta(days=2))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "subject.example")])
    if issuer_cn is None:
        # An issuer with no CN at all — only an organizationName.
        issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "No CN Org")])
    else:
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(nb + timedelta(days=90))
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san]),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def _cert_none_ssl_obj(der: bytes | None) -> MagicMock:
    """Fakes an SSLObject under CERT_NONE: dict form is empty, DER form works."""
    obj = MagicMock(spec=ssl.SSLObject)
    obj.getpeercert.side_effect = lambda binary_form=False: der if binary_form else {}
    return obj


def test_inspect_cert_none_ssl_obj():
    assert Resolver._inspect_cert(None, "example.com") == (None, None, None)


def test_inspect_cert_getpeercert_raises():
    obj = MagicMock(spec=ssl.SSLObject)
    obj.getpeercert.side_effect = ssl.SSLError("boom")
    assert Resolver._inspect_cert(obj, "example.com") == (None, None, None)


def test_inspect_cert_no_peer_cert():
    """binary_form=True returns None when the peer sent no certificate."""
    assert Resolver._inspect_cert(_cert_none_ssl_obj(None), "example.com") == (
        None,
        None,
        None,
    )


def test_inspect_cert_malformed_der():
    obj = _cert_none_ssl_obj(b"\x30\x03garbage-not-a-certificate")
    assert Resolver._inspect_cert(obj, "example.com") == (None, None, None)


def test_inspect_cert_reads_der_under_cert_none():
    """THE regression test for the cert-signal bug: under CERT_NONE the dict form
    is empty, so the signals silently blanked in production while dict-mocking
    tests stayed green. The reader must extract everything from the DER form."""
    obj = _cert_none_ssl_obj(_make_der_cert())
    issuer, age, san_match = Resolver._inspect_cert(obj, "lookalike.example.com")
    assert issuer == "Test CA"
    assert age is not None
    assert san_match is True


def test_inspect_cert_full_match():
    der = _make_der_cert(
        issuer_cn="Let's Encrypt",
        not_before=datetime.now(timezone.utc) - timedelta(days=2),
        san=("lookalike.example.com",),
    )
    issuer, age, san_match = Resolver._inspect_cert(
        _cert_none_ssl_obj(der), "lookalike.example.com"
    )
    assert issuer == "Let's Encrypt"
    assert age is not None and 1 <= age <= 3
    assert san_match is True


def test_inspect_cert_san_mismatch():
    der = _make_der_cert(issuer_cn="DigiCert", san=("totally-other.example",))
    issuer, _age, san_match = Resolver._inspect_cert(
        _cert_none_ssl_obj(der), "lookalike.example.com"
    )
    assert issuer == "DigiCert"
    assert san_match is False


def test_inspect_cert_san_wildcard_match():
    der = _make_der_cert(issuer_cn="DigiCert", san=("*.example.com",))
    _, _, san_match = Resolver._inspect_cert(_cert_none_ssl_obj(der), "sub.example.com")
    assert san_match is True


def test_inspect_cert_no_san_extension():
    der = _make_der_cert(san=None)
    _, _, san_match = Resolver._inspect_cert(_cert_none_ssl_obj(der), "x.example.com")
    assert san_match is None


def test_inspect_cert_issuer_without_cn():
    der = _make_der_cert(issuer_cn=None)
    issuer, age, _ = Resolver._inspect_cert(_cert_none_ssl_obj(der), "x.example.com")
    assert issuer is None
    assert age is not None  # the other signals still come through


# ---------------------------------------------------------------------------
# _read_capped — the bomb defense
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_capped_truncates_oversized_body():
    """A response advertising 2x the cap is read only up to the cap."""
    body = b"A" * (_MAX_BODY_BYTES * 2)
    with respx.mock(assert_all_called=False) as r:
        r.get("https://x.example.com/").mock(return_value=httpx.Response(200, content=body))
        async with httpx.AsyncClient() as client:
            async with client.stream("GET", "https://x.example.com") as resp:
                text = await Resolver._read_capped(resp)
    assert len(text) <= _MAX_BODY_BYTES


# ---------------------------------------------------------------------------
# _probe_http — both schemes raced; first finishing wins
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_probe_http_returns_first_successful_scheme():
    async with Resolver() as r:
        with respx.mock(assert_all_called=False) as mock_router:
            mock_router.get("https://x.example.com/").mock(
                return_value=httpx.Response(
                    200,
                    content=b"<title>Hi</title>",
                    headers={"server": "nginx"},
                )
            )
            mock_router.get("http://x.example.com/").mock(
                return_value=httpx.Response(503),
            )
            status, server, _redirect, title = await r._probe_http("x.example.com")
    assert status == 200
    assert server == "nginx"
    assert title == "Hi"


@pytest.mark.asyncio
async def test_probe_http_both_fail_returns_none_tuple():
    async with Resolver() as r:
        with respx.mock(assert_all_called=False) as mock_router:
            mock_router.get("https://x.example.com/").mock(
                side_effect=httpx.ConnectError("boom"),
            )
            mock_router.get("http://x.example.com/").mock(
                side_effect=httpx.ConnectError("boom"),
            )
            outcome = await r._probe_http("x.example.com")
    assert outcome == (None, None, None, None)


@pytest.mark.asyncio
async def test_probe_http_strips_unsafe_chars_from_location_header():
    """A hostile Location header can carry raw control/format chars (e.g. an
    ANSI escape or RTL override) — _probe_http must sanitize it before it
    becomes redirects_to, same as it already does for the page title.

    httpx/h11 already refuses to parse a real response whose header bytes
    are invalid, so the hostile value is injected directly at the
    ``http.stream()`` boundary instead of round-tripped through respx.
    """

    class _FakeHeaders(dict):
        def get(self, key, default=None):
            return super().get(key.lower(), default)

    class _FakeResp:
        status_code = 302
        headers = _FakeHeaders(location="https://evil\x1b[31m.example/")

    class _FakeStream:
        async def __aenter__(self):
            return _FakeResp()

        async def __aexit__(self, *exc):
            return False

    async with Resolver() as r:
        with patch.object(r._http, "stream", return_value=_FakeStream()):
            _status, _server, redirect, _title = await r._probe_http("x.example.com")
    assert redirect == "https://evil[31m.example/"


@pytest.mark.asyncio
async def test_probe_http_outside_context_manager_raises():
    r = Resolver()
    with pytest.raises(RuntimeError):
        await r._probe_http("x.example.com")


@pytest.mark.asyncio
async def test_probe_http_propagates_unexpected_exception():
    """httpx.HTTPError/UnicodeError/OSError/TimeoutError are graceful-degradation
    signals and get swallowed into a None tuple; anything else is a genuine bug
    and must surface to check_one's outer handler instead of being hidden."""
    async with Resolver() as r:
        with respx.mock(assert_all_called=False) as mock_router:
            mock_router.get("https://x.example.com/").mock(side_effect=ValueError("bug"))
            mock_router.get("http://x.example.com/").mock(side_effect=ValueError("bug"))
            with pytest.raises(ValueError, match="bug"):
                await r._probe_http("x.example.com")


# ---------------------------------------------------------------------------
# check_one — the unregistered-domain fast path (no IP, no MX): probing and
# WHOIS must both be skipped entirely.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_one_unregistered_domain_skips_probe_and_whois():
    perm = Permutation(domain="doesnotexist-otacon.com", kind=PermutationType.TYPO)
    async with Resolver() as r:
        with (
            patch.object(r, "_resolve_a", new_callable=AsyncMock, return_value=[]),
            patch.object(r, "_resolve_mx", new_callable=AsyncMock, return_value=[]),
            patch.object(r, "_probe", new_callable=AsyncMock) as mock_probe,
            patch("otacon.resolver.fetch_domain_age", new_callable=AsyncMock) as mock_whois,
        ):
            result = await r.check_one(perm)
    assert result.resolves is False
    assert result.has_mx is False
    assert result.is_registered is False
    mock_probe.assert_not_awaited()
    mock_whois.assert_not_awaited()


@pytest.mark.asyncio
async def test_check_one_outer_catch_degrades_to_blank_result_on_catastrophic_error():
    """A single variant blowing up (anything unexpected, not just network
    errors) must not crash the scan — check_one's outer handler degrades to a
    blank DomainResult instead of propagating."""
    perm = Permutation(domain="paypal.com", kind=PermutationType.TYPO)
    async with Resolver() as r:
        with (
            patch.object(
                r, "_resolve_a", new_callable=AsyncMock, side_effect=RuntimeError("catastrophic")
            ),
            patch.object(r, "_resolve_mx", new_callable=AsyncMock, return_value=[]),
        ):
            result = await r.check_one(perm)
    assert result.domain == "paypal.com"
    assert result.kind == PermutationType.TYPO
    assert result.resolves is False
    assert result.is_registered is False


# ---------------------------------------------------------------------------
# _check_ssl — exercises the success path with a faked ssl_object
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_ssl_open_connection_failure():
    """A connection error returns the all-None failure tuple."""
    async with Resolver() as r:
        with patch(
            "otacon.resolver.asyncio.open_connection",
            side_effect=OSError("refused"),
        ):
            ok, issuer, age, san_match = await r._check_ssl("x.example.com", "203.0.113.9")
    assert ok is False
    assert issuer is None and age is None and san_match is None


@pytest.mark.asyncio
async def test_check_ssl_success_returns_cert_metadata():
    """Patch open_connection to deliver a writer whose ssl_object has a cert."""
    fake_ssl_obj = _cert_none_ssl_obj(
        _make_der_cert(issuer_cn="Let's Encrypt", san=("x.example.com",))
    )
    writer = MagicMock()
    writer.get_extra_info.return_value = fake_ssl_obj
    writer.close = MagicMock()

    async def fake_wait_closed():
        return None

    writer.wait_closed = fake_wait_closed
    reader = MagicMock()

    async def fake_open_connection(*args, **kwargs):
        return reader, writer

    async with Resolver() as r:
        with patch("otacon.resolver.asyncio.open_connection", fake_open_connection):
            ok, issuer, _age, san_match = await r._check_ssl("x.example.com", "203.0.113.9")
    assert ok is True
    assert issuer == "Let's Encrypt"
    assert san_match is True
    writer.close.assert_called_once()


# ---------------------------------------------------------------------------
# SSRF guard — a lookalike resolving to an internal/metadata IP must never be
# actually dialed, even though DNS itself legitimately "resolved".
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_one_skips_probe_when_only_internal_ip_resolves():
    """A registered lookalike whose A record points at an internal address
    (e.g. an attacker aiming the scanner at 10.x/169.254.169.254) must be
    reported as resolving — that's real, useful signal — but never dialed."""
    perm = Permutation(domain="internal-lookalike.example", kind=PermutationType.COMBO)
    async with Resolver(check_http=True) as r:
        with _patch_network(r, resolve_ips=["10.0.0.5"]):
            with patch.object(
                r,
                "_probe_wildcard",
                new_callable=AsyncMock,
                return_value=frozenset(),
            ):
                # Undo _patch_network's _check_ssl/_probe_http mocks so we can
                # prove the *real* _probe() skip-logic is what stops the dial —
                # if it tried to connect, these unmocked calls would raise.
                with patch.object(
                    r,
                    "_check_ssl",
                    side_effect=AssertionError("must not dial an internal IP"),
                ):
                    with patch.object(
                        r,
                        "_probe_http",
                        side_effect=AssertionError("must not dial an internal IP"),
                    ):
                        result = await r.check_one(perm)
    assert result.resolves is True
    assert result.ip_addresses == ["10.0.0.5"]
    assert result.has_ssl is False
    assert result.http_status is None


@pytest.mark.asyncio
async def test_probe_returns_no_op_tuple_when_no_safe_ip():
    async with Resolver() as r:
        (ssl_ok, issuer, age, san), (status, server, redirect, title) = await r._probe(
            "internal.example", ["127.0.0.1"]
        )
    assert (ssl_ok, issuer, age, san) == (False, None, None, None)
    assert (status, server, redirect, title) == (None, None, None, None)
    assert "internal.example" not in r._ip_pins


@pytest.mark.asyncio
async def test_probe_returns_no_op_tuple_for_empty_ip_list():
    """Distinct from the no-safe-ip case above: no DNS answers at all, so the
    debug-log branch (which only fires when *ips* is non-empty) must not run."""
    async with Resolver() as r:
        (ssl_ok, issuer, age, san), (status, server, redirect, title) = await r._probe(
            "nxdomain.example", []
        )
    assert (ssl_ok, issuer, age, san) == (False, None, None, None)
    assert (status, server, redirect, title) == (None, None, None, None)


@pytest.mark.asyncio
async def test_probe_pins_and_uses_safe_ip():
    async with Resolver() as r:
        with patch.object(
            r,
            "_check_ssl",
            new_callable=AsyncMock,
            return_value=(True, None, None, None),
        ) as mock_ssl:
            with patch.object(
                r,
                "_probe_http",
                new_callable=AsyncMock,
                return_value=(200, None, None, None),
            ):
                await r._probe("lookalike.example", ["8.8.8.8"])
    assert r._ip_pins["lookalike.example"] == "8.8.8.8"
    mock_ssl.assert_awaited_once_with("lookalike.example", "8.8.8.8")


# ---------------------------------------------------------------------------
# _PinnedNetworkBackend — the httpcore-level enforcement point for the pin
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pinned_network_backend_refuses_unpinned_host():
    from otacon.resolver import _PinnedNetworkBackend

    backend = _PinnedNetworkBackend({})
    with pytest.raises(Exception, match="refusing unpinned connect"):
        await backend.connect_tcp("unpinned.example", 443)


@pytest.mark.asyncio
async def test_pinned_network_backend_connects_to_pinned_ip():
    from otacon.resolver import _PinnedNetworkBackend

    backend = _PinnedNetworkBackend({"lookalike.example": "203.0.113.9"})
    with patch.object(
        backend._delegate,
        "connect_tcp",
        new_callable=AsyncMock,
    ) as mock_connect:
        await backend.connect_tcp("lookalike.example", 443)
    mock_connect.assert_awaited_once_with(
        "203.0.113.9", 443, timeout=None, local_address=None, socket_options=None
    )


@pytest.mark.asyncio
async def test_pinned_network_backend_delegates_sleep():
    """httpcore's pool calls backend.sleep() for retry back-off; the base class
    raises NotImplementedError, so the pin backend must delegate it."""
    from otacon.resolver import _PinnedNetworkBackend

    backend = _PinnedNetworkBackend({})
    await backend.sleep(0)  # must not raise NotImplementedError


def test_pinned_http_transport_wires_backend_into_pool():
    """_PinnedHTTPTransport.__init__ reaches into httpx's private
    ``AsyncHTTPTransport._pool._network_backend`` attribute — httpx exposes no
    supported extension point for this. The unit tests above only exercise
    _PinnedNetworkBackend in isolation; nothing else in the suite would notice
    if a future httpx/httpcore release renamed that attribute and this
    assignment silently became a no-op, quietly disabling the SSRF pin for
    every real probe. Assert the wiring actually lands where we expect."""
    from otacon.resolver import _PinnedHTTPTransport, _PinnedNetworkBackend

    pins: dict[str, str] = {"lookalike.example": "203.0.113.9"}
    transport = _PinnedHTTPTransport(pins, verify=False)
    backend = transport._pool._network_backend
    assert isinstance(backend, _PinnedNetworkBackend)
    assert backend._pins is pins  # same dict object — live updates must be visible


# ---------------------------------------------------------------------------
# _query_ips / _resolve_mx — the raw aiodns.query() wrappers behind
# _resolve_a / _resolve_mx. Every other test mocks these away entirely; these
# exercise the actual success and exception-swallowing branches.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_ips_returns_hosts_from_records():
    r = Resolver()
    records = [MagicMock(host="1.2.3.4"), MagicMock(host="1.2.3.5")]
    with patch.object(r._dns, "query", new_callable=AsyncMock, return_value=records):
        ips = await r._query_ips("example.com", "A")
    assert ips == ["1.2.3.4", "1.2.3.5"]


@pytest.mark.asyncio
async def test_query_ips_swallows_any_exception():
    r = Resolver()
    with patch.object(r._dns, "query", new_callable=AsyncMock, side_effect=RuntimeError("boom")):
        ips = await r._query_ips("example.com", "AAAA")
    assert ips == []


@pytest.mark.asyncio
async def test_resolve_mx_returns_hosts_from_records():
    r = Resolver()
    records = [MagicMock(host="mail.example.com")]
    with patch.object(r._dns, "query", new_callable=AsyncMock, return_value=records):
        mx = await r._resolve_mx("example.com")
    assert mx == ["mail.example.com"]


@pytest.mark.asyncio
async def test_resolve_mx_swallows_any_exception():
    r = Resolver()
    with patch.object(r._dns, "query", new_callable=AsyncMock, side_effect=RuntimeError("boom")):
        mx = await r._resolve_mx("example.com")
    assert mx == []


# ---------------------------------------------------------------------------
# _probe_wildcard — runs for real here (other tests stub it out entirely via
# patch.object(r, "_probe_wildcard", ...)), covering both the "hijacker
# detected" and "clean resolver" branches.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_probe_wildcard_detects_hijacking_resolver():
    r = Resolver()
    with patch.object(r, "_resolve_a", new_callable=AsyncMock, return_value=["203.0.113.50"]):
        ips = await r._probe_wildcard()
    assert ips == frozenset({"203.0.113.50"})


@pytest.mark.asyncio
async def test_probe_wildcard_clean_resolver_returns_empty():
    r = Resolver()
    with patch.object(r, "_resolve_a", new_callable=AsyncMock, return_value=[]):
        ips = await r._probe_wildcard()
    assert ips == frozenset()


# ---------------------------------------------------------------------------
# _fetch_target_title — wired up by __aenter__ when check_http and target are
# both set; covers the success path and the broad exception guard.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aenter_fetches_target_title_when_check_http_and_target_set():
    with patch.object(Resolver, "_resolve_a", new_callable=AsyncMock, return_value=["203.0.113.9"]):
        probe_ret = ((True, None, None, None), (200, None, None, "Example Domain"))
        with patch.object(Resolver, "_probe", new_callable=AsyncMock, return_value=probe_ret):
            async with Resolver(check_http=True, target="example.com") as r:
                pass
    assert r.target_title == "Example Domain"


@pytest.mark.asyncio
async def test_aenter_skips_target_title_without_target():
    async with Resolver(check_http=True, target="") as r:
        pass
    assert r.target_title is None


@pytest.mark.asyncio
async def test_target_title_property_is_read_only():
    """Callers (scoring, the scan loop) consume target_title but must not set it —
    the resolver owns the fetch. Async because constructing a Resolver builds an
    aiodns resolver, which needs a running loop."""
    r = Resolver(target="example.com")
    with pytest.raises(AttributeError):
        r.target_title = "spoofed"  # type: ignore[misc]


@pytest.mark.asyncio
async def test_fetch_target_title_returns_none_on_exception():
    r = Resolver(target="example.com")
    with patch.object(r, "_resolve_a", new_callable=AsyncMock, side_effect=RuntimeError("boom")):
        title = await r._fetch_target_title()
    assert title is None


# ---------------------------------------------------------------------------
# Live-network regression test — excluded by default (addopts: -m 'not network');
# run explicitly with `pytest -m network`. Exists because the cert-signal bug
# was invisible to every mocked test and only showed on a real handshake.
# ---------------------------------------------------------------------------


@pytest.mark.network
@pytest.mark.asyncio
async def test_live_check_ssl_extracts_real_issuer():
    from otacon._validate import first_safe_ip

    async with Resolver(check_http=True) as r:
        ips = await r._resolve_a("example.com")
        safe_ip = first_safe_ip(ips)
        assert safe_ip is not None, f"example.com resolved to no safe IP: {ips}"
        ok, issuer, age, san_match = await r._check_ssl("example.com", safe_ip)

    assert ok is True
    assert issuer is not None, "issuer must come from the DER form under CERT_NONE"
    assert age is not None and age >= 0
    assert san_match is True
