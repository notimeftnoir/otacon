"""Architecture and security verification tests for Otacon v2.0 modernization."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from otacon.core.exceptions import (
    ConfigurationError,
    DNSResolutionError,
    HTTPProbeError,
    OtaconError,
    PermutationError,
    ReportExportError,
    ResolutionError,
    ScoringError,
    SecurityError,
    SSRFBlockedError,
    TLSProbeError,
    ValidationError,
    WhoisError,
)
from otacon.core.models import (
    DomainResult,
    Permutation,
    ScanReport,
)
from otacon.core.types import PermutationType, RiskLevel
from otacon.engine.pool import ResourceLimiter
from otacon.net.security import first_safe_ip
from otacon.permutations.idn import idn_squats, to_ace
from otacon.reporters.csv import _csv_safe
from otacon.scoring.config import ScoringWeights

# ---------------------------------------------------------------------------
# 1. Exception Hierarchy
# ---------------------------------------------------------------------------


def test_exception_hierarchy() -> None:
    assert issubclass(ResolutionError, OtaconError)
    assert issubclass(DNSResolutionError, ResolutionError)
    assert issubclass(TLSProbeError, ResolutionError)
    assert issubclass(HTTPProbeError, ResolutionError)
    assert issubclass(WhoisError, ResolutionError)

    assert issubclass(SecurityError, OtaconError)
    assert issubclass(SSRFBlockedError, SecurityError)

    assert issubclass(ValidationError, OtaconError)
    assert issubclass(PermutationError, OtaconError)
    assert issubclass(ScoringError, OtaconError)
    assert issubclass(ConfigurationError, OtaconError)
    assert issubclass(ReportExportError, OtaconError)


# ---------------------------------------------------------------------------
# 2. Schema Boundary Validation & Immutability
# ---------------------------------------------------------------------------


def test_permutation_schema_roundtrip() -> None:
    p = Permutation(domain="test.com", kind=PermutationType.TYPO, note="keyboard typo")
    dumped = p.model_dump()
    assert dumped["domain"] == "test.com"
    assert dumped["kind"] == "typo"

    json_str = p.model_dump_json()
    reconstructed = Permutation.model_validate_json(json_str)
    assert reconstructed.domain == p.domain
    assert reconstructed.kind == p.kind


def test_domain_result_schema_roundtrip() -> None:
    now = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
    dr = DomainResult(
        domain="evil-example.com",
        kind=PermutationType.COMBO,
        resolves=True,
        ip_addresses=["93.184.216.34"],
        has_mx=True,
        mx_records=["mail.evil-example.com"],
        has_ssl=True,
        http_status=200,
        page_title="Example Domain",
        created_at=now,
        age_days=5,
        risk_score=75,
        risk_level=RiskLevel.HIGH,
        risk_reasons=["technique: combosquat (+20)", "resolves to an IP (+10)"],
    )
    dumped = dr.model_dump()
    assert dumped["domain"] == "evil-example.com"
    assert dr.is_registered is True

    json_str = dr.model_dump_json()
    reconstructed = DomainResult.model_validate_json(json_str)
    assert reconstructed.domain == dr.domain
    assert reconstructed.risk_score == 75
    assert reconstructed.is_registered is True


def test_scan_report_schema_roundtrip() -> None:
    dr = DomainResult(domain="fake.com", kind=PermutationType.TYPO, resolves=True, risk_score=20)
    report = ScanReport(
        target="example.com",
        total_permutations=100,
        results=[dr],
        dns_hijack_detected=False,
    )
    dumped = report.model_dump()
    assert dumped["target"] == "example.com"
    assert len(dumped["results"]) == 1

    json_str = report.model_dump_json()
    reconstructed = ScanReport.model_validate_json(json_str)
    assert reconstructed.target == report.target
    assert len(reconstructed.results) == 1
    assert reconstructed.results[0].domain == "fake.com"


# ---------------------------------------------------------------------------
# 3. SSRF Vetting & IP Filtering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ips", "expected"),
    [
        (["127.0.0.1", "10.0.0.1", "192.168.1.1"], None),
        (["169.254.169.254"], None),
        (["::1"], None),
        (["fc00::1"], None),
        (["fe80::1"], None),
        (["10.1.2.3", "93.184.216.34", "172.16.0.1"], None),
        (["93.184.216.34", "151.101.1.69"], "93.184.216.34"),
        (["2606:2800:220:1:248:1893:25c8:1946"], "2606:2800:220:1:248:1893:25c8:1946"),
        (["invalid-ip-string", "93.184.216.34"], "93.184.216.34"),
        ([], None),
    ],
)
def test_first_safe_ip_filtering(ips: list[str], expected: str | None) -> None:
    assert first_safe_ip(ips) == expected


# ---------------------------------------------------------------------------
# 4. ReDoS-Free HTML Head Parser
# ---------------------------------------------------------------------------


def test_safe_head_parser_handles_nested_and_malformed_html() -> None:
    from otacon.net.content import _parse_title

    html = "<html><head><title>Secure Sign In &amp; Login</title></head>"
    title = _parse_title(html)
    assert title == "Secure Sign In & Login"


def test_safe_head_parser_detects_login_form() -> None:
    from otacon.net.content import detect_login_form, extract_favicon_url

    html = (
        "<html><head><title>Portal</title>"
        '<link rel="shortcut icon" href="/assets/favicon.ico">'
        '</head><body><form method="POST">'
        '<input type="password" name="secret"></form></body></html>'
    )
    assert detect_login_form(html) is True
    assert (
        extract_favicon_url("https://example.com", html) == "https://example.com/assets/favicon.ico"
    )


def test_safe_head_parser_pathological_input() -> None:
    from otacon.net.content import _parse_title

    # 1,000 unclosed tags (< 64KB body chunk) — linear time test against regex ReDoS
    pathological = "<tag attr='value'>" * 1000 + "<title>Resilient Page</title>"
    assert _parse_title(pathological) == "Resilient Page"


# ---------------------------------------------------------------------------
# 5. IDN & Punycode (UTS #46)
# ---------------------------------------------------------------------------


def test_to_ace_uts46() -> None:
    # ASCII domain remains ASCII
    assert to_ace("example.com") == "example.com"
    # Cyrillic homoglyph (CYRILLIC SMALL LETTER A = U+0430)
    assert to_ace("\u0430pple.com") == "xn--pple-43d.com"
    # Leading/trailing dots preserved
    assert to_ace("sub.\u0430pple.com.") == "sub.xn--pple-43d.com."


def test_idn_squats_produces_ace_encoded_domains() -> None:
    variants = ["\u0430pple.com", "appl\u0435.com"]
    ace_results = idn_squats(variants)
    assert all(d.startswith("xn--") or ".xn--" in d for d in ace_results)


# ---------------------------------------------------------------------------
# 6. Adaptive OS FD Concurrency Pool
# ---------------------------------------------------------------------------


# patch() resolves its target by importing it, so these three cannot even be
# collected on Windows, where `resource` does not exist. The Windows branch has
# its own test below.
_unix_only = pytest.mark.skipif(sys.platform == "win32", reason="resource is Unix-only")


@_unix_only
def test_resource_limiter_caps_when_limit_low() -> None:
    with patch("resource.getrlimit", return_value=(128, 256)):
        # (128 - 64) // 2 = 32 max safe concurrency
        concurrency = ResourceLimiter.compute_safe_concurrency(requested=100)
        assert concurrency == 32


@_unix_only
def test_resource_limiter_allows_when_limit_high() -> None:
    with patch("resource.getrlimit", return_value=(8192, 8192)):
        concurrency = ResourceLimiter.compute_safe_concurrency(requested=50)
        assert concurrency == 50


@_unix_only
def test_resource_limiter_graceful_on_os_error() -> None:
    with patch("resource.getrlimit", side_effect=OSError("Operation not permitted")):
        concurrency = ResourceLimiter.compute_safe_concurrency(requested=75)
        assert concurrency == 75


def test_resource_limiter_returns_request_unchanged_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows exposes no FD ceiling, so the requested concurrency passes through."""
    monkeypatch.setattr(sys, "platform", "win32")
    assert ResourceLimiter.compute_safe_concurrency(requested=500) == 500


def test_pool_does_not_import_resource_unguarded() -> None:
    """`resource` is Unix-only; an unguarded module-level import kills Windows.

    engine.scanner imports ResourceLimiter, so a ModuleNotFoundError here took the
    whole CLI down on Windows — the platform the package classifiers advertise and
    the CI matrix builds. A source-level assertion is the honest guard: the bug was
    at import time, so no test that successfully imports the module can catch it on
    a Unix runner.
    """
    source = (
        Path(__file__).resolve().parent.parent / "src" / "otacon" / "engine" / "pool.py"
    ).read_text(encoding="utf-8")
    for line in source.splitlines():
        if line.startswith("import resource"):
            pytest.fail("pool.py imports `resource` at module level; guard it with sys.platform")
    assert 'if sys.platform != "win32":' in source


# ---------------------------------------------------------------------------
# 7. CSV Formula Injection Defense
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("input_val", "expected"),
    [
        ("=1+1", "'=1+1"),
        ("+cmd", "'+cmd"),
        ("-calc", "'-calc"),
        ("@SUM(A1:A10)", "'@SUM(A1:A10)"),
        ("\t=cmd", "'\t=cmd"),
        ("Normal text", "Normal text"),
        ("https://example.com", "https://example.com"),
    ],
)
def test_csv_safe_formula_neutralization(input_val: str, expected: str) -> None:
    assert _csv_safe(input_val) == expected


# ---------------------------------------------------------------------------
# 8. Scoring Overrides Type Safety
# ---------------------------------------------------------------------------


def test_scoring_weights_type_check() -> None:
    with pytest.raises(TypeError, match="overrides must be a dict"):
        ScoringWeights(overrides="invalid-string")  # type: ignore[arg-type]

    # Valid dictionary override
    weights = ScoringWeights(overrides={"points_resolves": 25})
    assert weights.points_resolves == 25
    # Unrecognized key is ignored gracefully
    weights2 = ScoringWeights(overrides={"invalid_key": 99})
    assert not hasattr(weights2, "invalid_key")


# ---------------------------------------------------------------------------
# 9. CLI Dispatch & Scanner Generator Resolution
# ---------------------------------------------------------------------------


def test_scanner_get_generate_fn_avoids_cli_generate_command() -> None:
    import otacon.cli  # noqa: F401  # ensures otacon.cli is imported and in sys.modules
    from otacon.engine.scanner import _get_generate_fn
    from otacon.permutations.generator import generate

    fn = _get_generate_fn()
    # Must NOT be the Typer CLI command function
    assert fn is generate
    # Must be callable with (domain, exclude=...)
    perms = fn("example.com")
    assert len(perms) > 0
    assert perms[0].domain != "example.com"
