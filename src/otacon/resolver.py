"""Resolver — asynchronously checks domain variants against the network.

For each variant it collects signals indicating registration and intent:
  - A record (whether it resolves)
  - MX record (readiness for email phishing)
  - SSL certificate on :443 (active HTTPS service)
  - HTTP(S) response + Server header + redirect

Async-first architecture: hundreds of variants checked concurrently with a
limit (semaphore) so we don't flood DNS/the network. Sequentially this would
take minutes; here, seconds.
"""

from __future__ import annotations

import asyncio
import contextlib
import html as _html
import logging
import re
import secrets
import ssl
import unicodedata
from datetime import datetime, timezone
from typing import Any, Literal

import aiodns
import httpcore
import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID

from . import __version__
from ._validate import first_safe_ip
from .models import DomainResult, Permutation
from .whois import fetch_domain_age

_log = logging.getLogger("otacon.resolver")

_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,200})", re.IGNORECASE)
_TITLE_MAX = 80
# Unicode general categories unsafe to echo verbatim to a terminal: Cc covers
# C0 *and* C1 control bytes (e.g. ESC and its 8-bit CSI equivalent U+009B),
# Cf covers format chars like U+202E (right-to-left override, used to spoof
# displayed text), Zl/Zp cover line/paragraph separators.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _strip_unsafe_chars(text: str) -> str:
    """Strips control/format/line-separator characters a hostile HTTP response
    could use to inject terminal escape sequences or spoof displayed text —
    applied to any attacker-controlled string printed verbatim (page title,
    redirect Location header)."""
    return "".join(ch for ch in text if unicodedata.category(ch) not in _UNSAFE_CATEGORIES)


def _parse_title(body: str) -> str | None:
    """Extracts and cleans <title> text from an HTML snippet. Returns None when absent."""
    m = _TITLE_RE.search(body)
    if not m:
        return None
    title = _strip_unsafe_chars(_html.unescape(" ".join(m.group(1).split())))
    return title[:_TITLE_MAX] if title else None


# Concurrency limit — protects against DNS resolver rate-limiting and file
# descriptor exhaustion.
DEFAULT_CONCURRENCY = 50
_DNS_TIMEOUT = 3.0
_HTTP_TIMEOUT = 4.0
# Wall-clock ceiling for one HTTP probe. httpx timeouts apply per read, so a
# hostile server trickling one byte per read could otherwise hold a concurrency
# slot almost indefinitely (slow-loris against the scanner).
_HTTP_DEADLINE = 15.0
# Hard cap on how much (decompressed) HTTP body we ever read. The page <title>
# lives in <head>, so 64 KB is plenty — and the cap is what stops a hostile
# lookalike server from OOM-ing the scanner with a giant body or a gzip bomb.
_MAX_BODY_BYTES = 65536


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Delegating backend that pins each connect to a pre-vetted, safe IP.

    Otacon's whole job is connecting to attacker-registered lookalikes, so a
    resolved A/AAAA record can legitimately point at 169.254.169.254 (cloud
    metadata) or an internal RFC1918 address — the SSRF guard applied
    to outbound connections applies equally here. *pins* is a live
    ``{hostname: safe_ip}`` map populated by the caller right before issuing a
    request for that host; a host with no vetted entry is refused rather than
    silently falling back to a fresh (unvetted) DNS lookup, which would reopen
    the DNS-rebinding window between the safety check and the actual connect.
    """

    def __init__(self, pins: dict[str, str]) -> None:
        self._pins = pins
        self._delegate = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        """Connects to the vetted IP pinned for *host*; refuses unpinned hosts."""
        ip = self._pins.get(host)
        if ip is None:
            raise httpcore.ConnectError(f"refusing unpinned connect to {host!r}")
        return await self._delegate.connect_tcp(
            ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )

    async def sleep(self, seconds: float) -> None:
        """The pool calls this for retry back-off; the base class raises."""
        await self._delegate.sleep(seconds)


class _PinnedHTTPTransport(httpx.AsyncHTTPTransport):
    """httpx transport whose connection pool routes every connect through the pin map."""

    def __init__(self, pins: dict[str, str], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._pool._network_backend = _PinnedNetworkBackend(pins)


class Resolver:
    """Concurrent domain checker. Holds shared resources (DNS, HTTP)."""

    def __init__(
        self,
        concurrency: int = DEFAULT_CONCURRENCY,
        check_http: bool = True,
        target: str = "",
    ) -> None:
        self._concurrency = concurrency
        self._sem = asyncio.Semaphore(concurrency)
        # _check_ssl uses asyncio.open_connection directly, so the httpx
        # connection-pool limits don't bound it — give TLS its own semaphore
        # so a pool of live hostile lookalikes can't blow past the OS fd cap.
        self._tls_sem = asyncio.Semaphore(concurrency)
        self._whois_sem = asyncio.Semaphore(4)
        self._dns = aiodns.DNSResolver(timeout=_DNS_TIMEOUT, tries=1)
        self._check_http = check_http
        self.target = target
        self._target_title: str | None = None
        # One HTTP client reused for all requests (connection pooling).
        self._http: httpx.AsyncClient | None = None
        # Per-run WHOIS cache — keyed by domain; stores an asyncio.Task so
        # concurrent check_one calls for the same domain share a single lookup.
        self._whois_cache: dict[str, asyncio.Task[tuple[datetime | None, int | None]]] = {}
        # Lazy wildcard-DNS canary (see _wildcard_ips) — created on first hit.
        self._wildcard_task: asyncio.Task[frozenset[str]] | None = None
        # {hostname: vetted safe IP} — populated just before probing a host so
        # _PinnedNetworkBackend can pin the HTTP connect (see _probe() below).
        self._ip_pins: dict[str, str] = {}

    async def _fetch_target_title(self) -> str | None:
        """Resolves and probes the target domain to fetch its page title.

        Routed through the same SSRF-safe pinning as lookalike variants — the
        target string ultimately still triggers a DNS lookup + outbound
        connection, so it gets no special trust.
        """
        try:
            ips = await self._resolve_a(self.target)
            # _probe returns (ssl_info, (status, server, redirect, title));
            # only the title is wanted here.
            _, (_, _, _, title) = await self._probe(self.target, ips)
            return title
        except Exception as exc:
            _log.debug("Failed to fetch target domain '%s' title: %r", self.target, exc)
            return None

    async def __aenter__(self) -> Resolver:
        transport = _PinnedHTTPTransport(
            self._ip_pins,
            # Probing typosquats means trusting their bad certs and inspecting them.
            verify=False,
            # Bound the connection pool to the scan's concurrency so a burst
            # of slow hostile hosts can't pile up file descriptors.
            limits=httpx.Limits(
                max_connections=self._concurrency,
                max_keepalive_connections=self._concurrency,
            ),
        )
        self._http = httpx.AsyncClient(
            transport=transport,
            timeout=_HTTP_TIMEOUT,
            follow_redirects=False,  # we want to see redirects, not follow them blindly
            headers={"User-Agent": f"Otacon/{__version__} (+domain-monitoring)"},
        )
        if self._check_http and self.target:
            self._target_title = await self._fetch_target_title()
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._http is not None:
            await self._http.aclose()

    async def _query_ips(self, domain: str, rtype: Literal["A", "AAAA"]) -> list[str]:
        """Runs a single A or AAAA query; returns IPs or [] on any DNS error."""
        try:
            records = await self._dns.query(domain, rtype)
            return [r.host for r in records]
        except Exception as exc:
            # pycares.AresError is not a subclass of aiodns.error.DNSError in all
            # versions, so we catch broadly — DNS queries are fire-and-forget.
            _log.debug("%s lookup failed for %s: %r", rtype, domain, exc)
            return []

    async def _resolve_a(self, domain: str) -> list[str]:
        """Returns IPv4 + IPv6 addresses (A and AAAA). Empty = does not resolve.

        AAAA matters: an IPv6-only lookalike resolves fine in every modern
        browser, so reporting it as unregistered would be a false negative.
        """
        v4, v6 = await asyncio.gather(self._query_ips(domain, "A"), self._query_ips(domain, "AAAA"))
        return v4 + v6

    async def _probe_wildcard(self) -> frozenset[str]:
        """Resolves a random nonexistent domain to detect NXDOMAIN hijacking.

        Some ISP/captive-portal resolvers answer every query with their own
        "search helper" IP, which would make *every* variant look registered.
        A nonce that should never exist exposes that: any IPs returned here are
        the hijacker's, and variants resolving only to them are treated as
        unregistered.
        """
        nonce = f"otacon-wildcard-{secrets.token_hex(8)}.com"
        ips = frozenset(await self._resolve_a(nonce))
        if ips:
            _log.debug("NXDOMAIN hijack detected: %s resolved to %s", nonce, sorted(ips))
        return ips

    async def _wildcard_ips(self) -> frozenset[str]:
        """Lazy, shared canary lookup — runs at most once per Resolver."""
        if self._wildcard_task is None:
            self._wildcard_task = asyncio.create_task(self._probe_wildcard())
        return await self._wildcard_task

    @property
    def target_title(self) -> str | None:
        """The target's own page title, fetched once on entry — ``None`` when HTTP
        probing is off or the fetch failed.

        Read-only on purpose: scoring compares each variant's title against it to
        spot cloned pages, so callers consume it but must never set it.
        """
        return self._target_title

    @property
    def dns_hijack_detected(self) -> bool:
        """True when the canary fired — the local resolver hijacks NXDOMAIN."""
        t = self._wildcard_task
        return bool(t is not None and t.done() and not t.cancelled() and t.result())

    async def _resolve_mx(self, domain: str) -> list[str]:
        """Returns MX records. Presence = the domain can send/receive mail."""
        try:
            records = await self._dns.query(domain, "MX")
            return [r.host for r in records]
        except Exception as exc:
            _log.debug("MX lookup failed for %s: %r", domain, exc)
            return []

    async def _check_ssl(
        self, domain: str, ip: str
    ) -> tuple[bool, str | None, int | None, bool | None]:
        """Probes :443 on *ip* (a pre-vetted safe address for *domain*) and inspects
        the served certificate — see ``_probe`` for why the connect is pinned to *ip*
        rather than letting ``asyncio.open_connection`` resolve *domain* itself.

        Returns ``(has_ssl, issuer_cn, cert_age_days, san_matches)``. A fresh cert
        (especially Let's Encrypt issued in the last week) is a strong phishing
        signal — attackers spin them up just before the campaign starts.
        SAN mismatch means the cert was issued for a different name and the
        attacker simply reused it — also a red flag.
        """
        async with self._tls_sem:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # Connect to the vetted IP directly; server_hostname keeps SNI
                # correct for virtual-hosted targets even though host is a literal.
                fut = asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=domain)
                _reader, writer = await asyncio.wait_for(fut, timeout=_HTTP_TIMEOUT)
                try:
                    ssl_obj = writer.get_extra_info("ssl_object")
                    issuer_cn, age_days, san_matches = self._inspect_cert(ssl_obj, domain)
                finally:
                    writer.close()
                    # Some hostile/odd TLS stacks reset on close — we already
                    # have the cert info we needed.
                    with contextlib.suppress(OSError, ssl.SSLError):
                        await writer.wait_closed()
                return True, issuer_cn, age_days, san_matches
            except (OSError, asyncio.TimeoutError, ssl.SSLError, UnicodeError):
                return False, None, None, None

    @staticmethod
    def _inspect_cert(
        ssl_obj: ssl.SSLObject | None, domain: str
    ) -> tuple[str | None, int | None, bool | None]:
        """Pulls issuer CN, notBefore age (days), and SAN-host match from a cert.

        Reads the DER form (``getpeercert(binary_form=True)``): the probe
        handshakes with ``CERT_NONE`` because hostile lookalikes have broken
        certs by design, and CPython returns an *empty dict* from the text
        form for unvalidated certs — which would silently blank all three
        signals.
        """
        if ssl_obj is None:
            return None, None, None
        try:
            der = ssl_obj.getpeercert(binary_form=True)
        except (ValueError, ssl.SSLError):
            return None, None, None
        if not der:
            return None, None, None
        try:
            cert = x509.load_der_x509_certificate(der)
        except ValueError:
            return None, None, None

        issuer_cn: str | None = None
        cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            raw = cn_attrs[0].value
            issuer_cn = raw if isinstance(raw, str) else raw.decode("utf-8", "replace")

        age_days: int | None = (datetime.now(timezone.utc) - cert.not_valid_before_utc).days

        san_matches: bool | None = None
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_names = [n.lower() for n in san_ext.value.get_values_for_type(x509.DNSName)]
        except (x509.ExtensionNotFound, x509.DuplicateExtension, ValueError):
            # No SAN, or a deliberately malformed extension block on a hostile cert.
            san_names = []
        if san_names:
            host = domain.lower().rstrip(".")
            san_matches = any(
                host == name or (name.startswith("*.") and host.endswith(name[1:]))
                for name in san_names
            )

        return issuer_cn, age_days, san_matches

    @staticmethod
    async def _read_capped(resp: httpx.Response) -> str:
        """Reads at most ``_MAX_BODY_BYTES`` of the (decompressed) body.

        Streaming + early break means we never materialise more than the cap in
        memory, even when the server advertises gzip and unpacks to gigabytes —
        httpx decompresses lazily as we iterate, so breaking stops the bomb.
        """
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if total >= _MAX_BODY_BYTES:
                break
        return b"".join(chunks)[:_MAX_BODY_BYTES].decode("utf-8", "replace")

    async def _probe_http(
        self, domain: str
    ) -> tuple[int | None, str | None, str | None, str | None]:
        """Tries HTTPS and HTTP in parallel. Returns (status, server, redirect, title)."""
        if self._http is None:
            raise RuntimeError("Resolver._probe_http called outside async context manager")

        http = self._http

        async def _get(scheme: str) -> tuple[int, str | None, str | None, str | None]:
            """Issues one capped GET; returns (status, server, redirect, title)."""
            # stream() so we can bound the body read — see _read_capped.
            async with http.stream("GET", f"{scheme}://{domain}") as resp:
                location = resp.headers.get("location")
                if location is not None:
                    location = _strip_unsafe_chars(location)
                server = resp.headers.get("server")
                title: str | None = None
                if 200 <= resp.status_code < 300:
                    title = _parse_title(await self._read_capped(resp))
                return resp.status_code, server, location, title

        # Check both schemes in parallel; each gets a hard wall-clock deadline
        # (httpx timeouts are per read — see _HTTP_DEADLINE). HTTPS wins ties.
        outcomes = await asyncio.gather(
            asyncio.wait_for(_get("https"), _HTTP_DEADLINE),
            asyncio.wait_for(_get("http"), _HTTP_DEADLINE),
            return_exceptions=True,
        )
        for outcome in outcomes:
            if not isinstance(outcome, BaseException):
                return outcome
            if not isinstance(
                outcome, (httpx.HTTPError, UnicodeError, OSError, asyncio.TimeoutError)
            ):
                raise outcome  # unexpected bug — surface it to check_one's logger

        return None, None, None, None

    async def _probe(
        self, domain: str, ips: list[str]
    ) -> tuple[
        tuple[bool, str | None, int | None, bool | None],
        tuple[int | None, str | None, str | None, str | None],
    ]:
        """Runs the SSL + HTTP probes for *domain*, pinned to a vetted IP from *ips*.

        SSRF guard: *domain* is an attacker-influenced hostname (a lookalike we
        generated, or even the operator's own target — see _fetch_target_title),
        so its DNS answer can't be trusted to route our own outbound connection.
        When no address in *ips* passes ``first_safe_ip`` (i.e. every answer is
        private/loopback/link-local/reserved — which covers 169.254.169.254
        cloud metadata), the probe is skipped entirely rather than connecting
        blind; DNS still "resolves" for scoring purposes, we just never dial out.
        """
        safe_ip = first_safe_ip(ips)
        if safe_ip is None:
            if ips:
                _log.debug(
                    "skipping HTTP/SSL probe for %s: no non-internal IP among %s", domain, ips
                )
            return (False, None, None, None), (None, None, None, None)

        self._ip_pins[domain] = safe_ip
        return await asyncio.gather(
            self._check_ssl(domain, safe_ip),
            self._probe_http(domain),
        )

    async def _fetch_whois(self, domain: str) -> tuple[datetime | None, int | None]:
        """WHOIS lookup bounded by ``self._whois_sem`` so we don't get rate-limited."""
        async with self._whois_sem:
            return await fetch_domain_age(domain)

    async def _cached_whois(self, domain: str) -> tuple[datetime | None, int | None]:
        """Returns WHOIS age data, deduplicated per domain per run."""
        if domain not in self._whois_cache:
            self._whois_cache[domain] = asyncio.create_task(self._fetch_whois(domain))
        return await self._whois_cache[domain]

    async def check_one(self, perm: Permutation) -> DomainResult:
        """Full check of a single variant. Bounded by the semaphore."""
        async with self._sem:
            try:
                result = DomainResult(domain=perm.domain, kind=perm.kind, note=perm.note)

                # MX is checked independently of A — mail-only phishing domains
                # often have MX but no A record (no web presence by design).
                ips, mx = await asyncio.gather(
                    self._resolve_a(perm.domain), self._resolve_mx(perm.domain)
                )

                if ips:
                    # Discard hits that only point at an NXDOMAIN-hijacking
                    # resolver's IPs — they'd register as false positives.
                    wildcard = await self._wildcard_ips()
                    if wildcard and set(ips) <= wildcard:
                        _log.debug("ignoring hijacked answer for %s: %s", perm.domain, ips)
                        ips = []

                result.ip_addresses = ips
                result.resolves = bool(ips)
                result.mx_records = mx
                result.has_mx = bool(mx)

                # SSL and HTTP only make sense when there's an IP to connect to.
                if result.resolves and self._check_http:
                    (
                        (ssl_ok, issuer, cert_age, san_match),
                        (status, server, redirect, title),
                    ) = await self._probe(perm.domain, ips)
                    result.has_ssl = ssl_ok
                    result.ssl_issuer = issuer
                    result.ssl_cert_age_days = cert_age
                    result.ssl_san_matches = san_match
                    result.http_status = status
                    result.server_header = server
                    result.redirects_to = redirect
                    result.page_title = title

                # WHOIS only for registered domains — unregistered aren't worth the quota.
                if result.is_registered:
                    created, age = await self._cached_whois(perm.domain)
                    result.created_at = created
                    result.age_days = age

                return result
            except Exception as exc:
                # Broad catch is intentional — an unhandled exception here would
                # close the shared httpx client and crash every other concurrent
                # check_one coroutine. Graceful degradation beats a precise catch.
                _log.debug("check_one failed for %s: %r", perm.domain, exc)
                return DomainResult(domain=perm.domain, kind=perm.kind, note=perm.note)
