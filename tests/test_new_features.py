"""Tests for features 1, 2, and 3:
1. Favicon MurmurHash3 hashing and login form detection.
2. Advanced Parking and Sinkhole classification.
3. Passive DNSBL (Spamhaus DBL & SURBL) reputation lookups.
"""

from __future__ import annotations

import pytest

from otacon.core.models import DomainResult
from otacon.core.types import PermutationType, RiskLevel
from otacon.net.content import detect_login_form, extract_favicon_url, mmh3_32, shodan_favicon_hash
from otacon.net.http import HTTPProbeResult
from otacon.net.resolver import Resolver
from otacon.scoring import score

# ---------------------------------------------------------------------------
# Feature 1: MurmurHash3 & Web Fingerprinting
# ---------------------------------------------------------------------------


def test_mmh3_32_reference_vectors() -> None:
    # Empty bytes -> 0
    assert mmh3_32(b"") == 0
    # "hello" with seed 0 -> 613153351
    assert mmh3_32(b"hello") == 613153351
    # Reference test vector: "The quick brown fox jumps over the lazy dog" -> 0x2e4ff723 (776992547)
    assert mmh3_32(b"The quick brown fox jumps over the lazy dog") == 776992547


def test_shodan_favicon_hash() -> None:
    # Shodan format encodes with base64 + newlines before applying mmh3
    sample_ico = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00testfavicon"
    fav_hash = shodan_favicon_hash(sample_ico)
    assert isinstance(fav_hash, int)
    assert fav_hash != 0
    assert shodan_favicon_hash(b"") == 0


def test_detect_login_form() -> None:
    html_pass = (
        '<html><form><input type="text" name="u"><input type="password" name="pw"></form></html>'
    )
    html_token = '<html><form><input type="text" name="access_token"></form></html>'
    html_clean = "<html><body><h1>Welcome to our blog</h1><p>Articles</p></body></html>"

    assert detect_login_form(html_pass) is True
    assert detect_login_form(html_token) is True
    assert detect_login_form(html_clean) is False
    assert detect_login_form("") is False


def test_extract_favicon_url() -> None:
    html1 = '<html><head><link rel="icon" href="/static/img/fav.png"></head></html>'
    html2 = (
        '<html><head><link href="https://example.com/icon.ico" rel="shortcut icon"></head></html>'
    )
    html3 = "<html><head><title>No icon</title></head></html>"

    assert (
        extract_favicon_url("https://target.com", html1) == "https://target.com/static/img/fav.png"
    )
    assert extract_favicon_url("https://target.com", html2) == "https://example.com/icon.ico"
    assert extract_favicon_url("https://target.com", html3) == "https://target.com/favicon.ico"


def test_scoring_cloned_favicon_and_login_form() -> None:
    result = DomainResult(
        domain="examp1e.com",
        kind=PermutationType.HOMOGLYPH,
        resolves=True,
        http_status=200,
        favicon_matches_target=True,
        has_login_form=True,
    )
    scored = score(result)
    assert scored.risk_score >= 80
    assert scored.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert any("favicon matches target" in r for r in scored.risk_reasons)
    assert any("login form" in r for r in scored.risk_reasons)


# ---------------------------------------------------------------------------
# Feature 2: Parking & Sinkhole Classifier
# ---------------------------------------------------------------------------


def test_parking_detected_via_nameservers() -> None:
    result = DomainResult(
        domain="example-buy.com",
        kind=PermutationType.COMBO,
        resolves=True,
        ns_records=["ns1.sedoparking.com", "ns2.sedoparking.com"],
        http_status=200,
    )
    scored = score(result)
    assert scored.is_parked is True
    assert any("detected as parked domain" in r for r in scored.risk_reasons)
    # HTTP signals are ignored for parked domains
    assert not any("active site" in r for r in scored.risk_reasons)


def test_parking_detected_via_ip() -> None:
    result = DomainResult(
        domain="example-sale.com",
        kind=PermutationType.COMBO,
        resolves=True,
        ip_addresses=["91.195.240.12"],  # Sedo IP range
        http_status=200,
    )
    scored = score(result)
    assert scored.is_parked is True


def test_sinkhole_neutralizes_threat() -> None:
    result = DomainResult(
        domain="evil-c2-example.com",
        kind=PermutationType.TYPO,
        resolves=True,
        has_mx=True,
        has_ssl=True,
        ns_records=["sinkhole.cert.pl"],
        ip_addresses=["127.0.0.1"],
    )
    scored = score(result)
    assert scored.is_sinkhole is True
    assert scored.risk_score == 0
    assert scored.risk_level == RiskLevel.SAFE
    assert any("sinkhole / law enforcement seizure detected" in r for r in scored.risk_reasons)


# ---------------------------------------------------------------------------
# Feature 3: Passive DNSBL (Spamhaus DBL & SURBL)
# ---------------------------------------------------------------------------


def test_scoring_dnsbl_hit() -> None:
    result = DomainResult(
        domain="bank-update-alert.com",
        kind=PermutationType.COMBO,
        resolves=True,
        dnsbl_listed=True,
        dnsbl_source="Spamhaus DBL (phishing)",
    )
    scored = score(result)
    assert scored.risk_score >= 70
    assert scored.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert any("listed on Spamhaus DBL (phishing)" in r for r in scored.risk_reasons)


@pytest.mark.asyncio
async def test_resolver_dnsbl_mock_hit() -> None:
    class _Record:
        def __init__(self, host: str) -> None:
            self.host = host

    async def mock_query(domain: str, rtype: str):
        if "dbl.spamhaus.org" in domain:
            return [_Record("127.0.1.4")]
        return []

    r = Resolver()
    r._dns.query_dns = mock_query  # type: ignore[assignment]
    listed, source = await r._check_dnsbl("evil.com")
    assert listed is True
    assert source == "Spamhaus DBL (phishing)"


@pytest.mark.asyncio
async def test_resolver_dnsbl_clean() -> None:
    async def mock_query(domain: str, rtype: str):
        raise RuntimeError("NXDOMAIN")

    r = Resolver()
    r._dns.query_dns = mock_query  # type: ignore[assignment]
    listed, source = await r._check_dnsbl("clean.com")
    assert listed is False
    assert source is None


def test_http_probe_result_tuple_compatibility() -> None:
    res = HTTPProbeResult(200, "nginx", "/login", "Title", True, 999)
    # Unpacks as 4 items for backward-compatibility
    s, srv, red, title = res
    assert s == 200
    assert srv == "nginx"
    assert red == "/login"
    assert title == "Title"
    assert res.has_login_form is True
    assert res.favicon_hash == 999
    assert len(res) == 4


# ---------------------------------------------------------------------------
# Phase 2 - Feature 4: Certificate Transparency (CT logs) Discovery
# ---------------------------------------------------------------------------


class _CTResponse:
    def __init__(self, payload, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class _CTClient:
    """crt.sh answers the brand-label search; Certspotter lists the target's own certs."""

    def __init__(self, crtsh, certspotter, certspotter_status: int = 200) -> None:
        self.crtsh = crtsh
        self.certspotter = certspotter
        self.certspotter_status = certspotter_status
        self.urls: list[str] = []

    async def get(self, url: str, **kwargs):
        self.urls.append(url)
        if "certspotter" in url:
            return _CTResponse(self.certspotter, self.certspotter_status)
        return _CTResponse(self.crtsh)

    async def aclose(self):
        pass


_CRTSH_HITS = [
    {"name_value": "*.target-verify.com\nlogin.target-verify.com"},
    {"name_value": "targetsupport.net"},
    {"name_value": "target.com\napi.target.com"},  # the target and its subdomains
    {"name_value": "targetcdn.net"},  # shares a certificate with target.com below
    {"name_value": "target.cdn.example.org"},  # label only in an unrelated site's subdomain
    {"name_value": "Target Corporation"},  # an organisation name, not a hostname
]


@pytest.mark.asyncio
async def test_fetch_ct_domains_finds_lookalikes_and_drops_own_infrastructure() -> None:
    from otacon.ct_logs import fetch_ct_domains

    client = _CTClient(_CRTSH_HITS, [{"dns_names": ["target.com", "www.targetcdn.net"]}])
    domains = await fetch_ct_domains("target.com", client=client)  # type: ignore[arg-type]
    # Collapsed to what was registered; the brand's own certificate excludes
    # targetcdn.net, which is how facebook.net stops being a lookalike of facebook.com.
    assert domains == {"target-verify.com", "targetsupport.net"}
    assert any("%25target%25" in u for u in client.urls)


@pytest.mark.asyncio
async def test_fetch_ct_domains_without_exclusion_list_still_drops_the_target() -> None:
    from otacon.ct_logs import fetch_ct_domains

    client = _CTClient(_CRTSH_HITS, [], certspotter_status=500)
    domains = await fetch_ct_domains("target.com", client=client)  # type: ignore[arg-type]
    assert domains == {"target-verify.com", "targetsupport.net", "targetcdn.net"}


@pytest.mark.asyncio
async def test_fetch_ct_domains_skips_labels_too_short_to_search() -> None:
    from otacon.ct_logs import fetch_ct_domains

    client = _CTClient(_CRTSH_HITS, [])
    assert await fetch_ct_domains("g.co", client=client) == set()  # type: ignore[arg-type]
    assert client.urls == []


def test_registrable_collapses_to_the_registered_name() -> None:
    from otacon.ct_logs import registrable

    assert registrable("a.b.login-target.com") == "login-target.com"
    assert registrable("shop.target.co.uk") == "target.co.uk"
    assert registrable("target.pl") == "target.pl"


@pytest.mark.asyncio
async def test_fetch_ct_domains_graceful_error_handling() -> None:
    from otacon.ct_logs import fetch_ct_domains

    class FailingClient:
        async def get(self, url: str):
            raise RuntimeError("Network unreachable")

        async def aclose(self):
            pass

    domains = await fetch_ct_domains("target.com", client=FailingClient())  # type: ignore[arg-type]
    assert domains == set()


# ---------------------------------------------------------------------------
# Phase 2 - Feature 5: Deep Email Security (SPF / DMARC & Spoofing Risk)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolver_email_security_dmarc_enforced() -> None:
    r = Resolver()

    async def mock_resolve_txt(domain: str) -> list[str]:
        if domain.startswith("_dmarc."):
            return ["v=DMARC1; p=reject; rua=mailto:dmarc@target.com"]
        return ["v=spf1 -all"]

    r._resolve_txt = mock_resolve_txt  # type: ignore[assignment]
    spf, spf_rec, dmarc, policy, spoofable = await r._check_email_security("target.com")
    assert spf is True
    assert spf_rec == "v=spf1 -all"
    assert dmarc is True
    assert policy == "reject"
    assert spoofable is False


@pytest.mark.asyncio
async def test_resolver_email_security_spoofable_none_policy() -> None:
    r = Resolver()

    async def mock_resolve_txt(domain: str) -> list[str]:
        if domain.startswith("_dmarc."):
            return ["v=DMARC1; p=none; rua=mailto:dmarc@target.com"]
        return []

    r._resolve_txt = mock_resolve_txt  # type: ignore[assignment]
    _spf, _spf_rec, dmarc, policy, spoofable = await r._check_email_security("spoofable.com")
    assert dmarc is True
    assert policy == "none"
    assert spoofable is True


def test_scoring_mail_spoofable() -> None:
    res = DomainResult(
        domain="target-bank.com",
        kind=PermutationType.COMBO,
        resolves=True,
        has_mx=True,
        is_mail_spoofable=True,
        dmarc_policy="none",
    )
    scored = score(res)
    assert any("email spoofing vector" in r for r in scored.risk_reasons)
    assert scored.risk_score >= 15


# ---------------------------------------------------------------------------
# Phase 2 - Feature 6: Scan Comparison / Diff Engine & CLI Command
# ---------------------------------------------------------------------------


def test_compute_diff() -> None:
    from datetime import UTC, datetime

    from otacon.core.models import ScanReport
    from otacon.diff import compute_diff

    t1 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    t2 = datetime(2026, 1, 2, 12, 0, tzinfo=UTC)

    old_rep = ScanReport(
        target="target.com",
        started_at=t1,
        results=[
            DomainResult(
                domain="target-old.com",
                kind=PermutationType.COMBO,
                resolves=True,
                risk_score=10,
                risk_level=RiskLevel.LOW,
            ),
            DomainResult(
                domain="target-dropped.com",
                kind=PermutationType.COMBO,
                resolves=True,
                risk_score=20,
                risk_level=RiskLevel.LOW,
            ),
        ],
    )

    new_rep = ScanReport(
        target="target.com",
        started_at=t2,
        results=[
            DomainResult(
                domain="target-old.com",
                kind=PermutationType.COMBO,
                resolves=True,
                has_mx=True,
                mx_records=["mail.target-old.com"],
                risk_score=60,
                risk_level=RiskLevel.HIGH,
            ),
            DomainResult(
                domain="target-new-threat.com",
                kind=PermutationType.TYPO,
                resolves=True,
                has_ssl=True,
                has_mx=True,
                risk_score=85,
                risk_level=RiskLevel.CRITICAL,
            ),
        ],
    )

    diff = compute_diff(old_rep, new_rep)
    assert diff.has_changes is True
    assert diff.has_critical_threat is True
    assert len(diff.new_domains) == 1
    assert diff.new_domains[0].domain == "target-new-threat.com"
    assert diff.new_domains[0].status == "new_threat"

    assert len(diff.dropped_domains) == 1
    assert diff.dropped_domains[0].domain == "target-dropped.com"

    assert len(diff.modified_domains) == 1
    mod = diff.modified_domains[0]
    assert mod.domain == "target-old.com"
    assert any("Mail server added" in c for c in mod.changes)
    assert any("Score shifted 10 → 60" in c for c in mod.changes)


def test_cli_diff_subcommand(tmp_path) -> None:
    from typer.testing import CliRunner

    from otacon.cli import app
    from otacon.core.models import DomainResult, ScanReport

    runner = CliRunner()

    rep1 = ScanReport(
        target="brand.com",
        results=[
            DomainResult(
                domain="brand-login.com",
                kind=PermutationType.COMBO,
                resolves=True,
                risk_score=10,
                risk_level=RiskLevel.LOW,
            )
        ],
    )
    rep2 = ScanReport(
        target="brand.com",
        results=[
            DomainResult(
                domain="brand-login.com",
                kind=PermutationType.COMBO,
                resolves=True,
                has_mx=True,
                risk_score=80,
                risk_level=RiskLevel.CRITICAL,
            )
        ],
    )

    f1 = tmp_path / "rep1.json"
    f2 = tmp_path / "rep2.json"
    diff_out = tmp_path / "diff.json"

    f1.write_text(rep1.model_dump_json(), encoding="utf-8")
    f2.write_text(rep2.model_dump_json(), encoding="utf-8")

    result = runner.invoke(app, ["diff", str(f1), str(f2), "--json", str(diff_out)])
    assert result.exit_code == 0
    assert "OTACON DIFF" in result.output
    assert diff_out.exists()

    # Test --fail-on-threats exits with code 2
    res_gate = runner.invoke(app, ["diff", str(f1), str(f2), "--fail-on-threats"])
    assert res_gate.exit_code == 2
