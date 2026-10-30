"""Concurrent network resolver coordinating DNS, TLS, HTTP, WHOIS, and threat reputation."""

from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime
from typing import Any, Literal

import aiodns
import httpx

from ..core.models import DomainResult, Permutation
from .content import _MAX_BODY_BYTES, _strip_unsafe_chars
from .dns import NULL_MX, is_negative_answer
from .dns import query_records as _query_dns
from .dnsbl import check_dnsbl
from .email_sec import check_email_security
from .http import (
    _REDIRECT_MAX,
    DEFAULT_HTTP_TIMEOUT,
    HTTP_DEADLINE,
    HTTPS_GRACE,
    USER_AGENT,
    HTTPProbeResult,
    probe_http,
    read_capped_body,
)
from .rdap import DEFAULT_RDAP_TIMEOUT
from .security import _PinnedHTTPTransport, first_safe_ip
from .tls import HTTPS_PORT, inspect_cert, probe_ssl
from .whois import fetch_domain_age

_log = logging.getLogger("otacon.net.resolver")

DEFAULT_CONCURRENCY = 50
# HTTP + HTTPS raced, plus one favicon fetch on a 2xx.
_CONNECTIONS_PER_PROBE = 3
_DNS_TIMEOUT = 3.0
_HTTP_TIMEOUT = DEFAULT_HTTP_TIMEOUT
_HTTPS_PORT = HTTPS_PORT
_HTTP_DEADLINE = HTTP_DEADLINE
_HTTPS_GRACE = HTTPS_GRACE


class Resolver:
    """Orchestrates asynchronous network checks over domain permutations."""

    def __init__(
        self,
        concurrency: int = DEFAULT_CONCURRENCY,
        check_http: bool = True,
        target: str = "",
        check_whois: bool = True,
        check_dnsbl: bool = True,
    ) -> None:
        self._concurrency = concurrency
        self._sem = asyncio.Semaphore(concurrency)
        self._tls_sem = asyncio.Semaphore(concurrency)
        self._whois_sem = asyncio.Semaphore(4)
        self._dns = aiodns.DNSResolver(timeout=_DNS_TIMEOUT, tries=1)
        self._check_http = check_http
        self._check_whois = check_whois
        self._enable_dnsbl = check_dnsbl
        self.target = target
        self._target_title: str | None = None
        self._target_favicon_hash: int | None = None
        self._http: httpx.AsyncClient | None = None
        self._rdap: httpx.AsyncClient | None = None
        self._wildcard_task: asyncio.Task[frozenset[str]] | None = None
        self._ip_pins: dict[str, str] = {}
        # Health of the DNS layer itself. Every swallowed lookup error here used
        # to be indistinguishable from "this domain does not exist", which is how
        # a library break shipped as a confident all-clear.
        self.dns_queries = 0
        self.dns_failures = 0
        # Same reasoning one level up: a probe that raises returns a blank
        # result, which reads as "nothing registered here" rather than
        # "this was never answered". Counted so the report can say so.
        self.probe_failures = 0
        # True once a reputation list declined to answer rather than
        # saying the domain was clean. See net.dnsbl._REFUSAL_PREFIX.
        self.dnsbl_refused = False

    async def _fetch_target_title(self) -> str | None:
        """Fetches page title and favicon hash of the target domain for cloned-site detection."""
        try:
            ips = await self._resolve_a(self.target)
            _, http_res = await self._probe(self.target, ips)
            self._target_favicon_hash = getattr(http_res, "favicon_hash", None)
            title = http_res[3]
            return str(title) if isinstance(title, str) else None
        except Exception as exc:
            _log.debug("Failed to fetch target domain '%s' title: %r", self.target, exc)
            return None

    async def __aenter__(self) -> Resolver:
        # A probe opens three connections, not one: probe_http races HTTP and
        # HTTPS, and a 2xx answer fetches the favicon as well. Sized at
        # `concurrency` the pool was a third of what the semaphore admits, so
        # probes queued for a slot — and at the pool timeout the PoolTimeout
        # read as "this host serves nothing".
        pool = self._concurrency * _CONNECTIONS_PER_PROBE
        transport = _PinnedHTTPTransport(
            self._ip_pins,
            verify=False,
            limits=httpx.Limits(max_connections=pool, max_keepalive_connections=pool),
        )
        self._http = httpx.AsyncClient(
            transport=transport,
            timeout=_HTTP_TIMEOUT,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        )
        # One client for every RDAP lookup in the scan. Built per domain it
        # meant a fresh TLS handshake to rdap.org for each one, which is the
        # slowest part of a scan of a busy brand. follow_redirects is required:
        # rdap.org always redirects to the authoritative registry.
        self._rdap = httpx.AsyncClient(
            follow_redirects=True,
            timeout=DEFAULT_RDAP_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        if self._check_http and self.target:
            self._target_title = await self._fetch_target_title()
        return self

    async def __aexit__(self, *exc: object) -> None:
        for client in (self._http, self._rdap):
            if client is not None:
                await client.aclose()

    async def fetch_ct_domains(self) -> set[str]:
        """Discovers certificates and lookalike domains via Certificate Transparency logs."""
        from ..ct_logs import fetch_ct_domains

        return await fetch_ct_domains(self.target)

    async def _query(self, domain: str, rtype: str) -> list[Any]:
        """Queries *rtype* for *domain*, counting the lookup and whether it answered.

        Every record type goes through here, so a resolver failing on MX, NS or
        TXT shows up in ``ScanReport.degraded`` just like one failing on A.
        """
        self.dns_queries += 1
        try:
            async with asyncio.timeout(_DNS_TIMEOUT):
                return await _query_dns(self._dns, domain, rtype)
        except Exception as exc:
            if not is_negative_answer(exc):
                self.dns_failures += 1
            _log.debug("%s lookup failed for %s: %r", rtype, domain, exc)
            return []

    async def _query_ips(self, domain: str, rtype: Literal["A", "AAAA"]) -> list[str]:
        return [r.host for r in await self._query(domain, rtype)]

    async def _resolve_a(self, domain: str) -> list[str]:
        async with asyncio.TaskGroup() as tg:
            t4 = tg.create_task(self._query_ips(domain, "A"))
            t6 = tg.create_task(self._query_ips(domain, "AAAA"))
        return t4.result() + t6.result()

    async def _probe_wildcard(self) -> frozenset[str]:
        nonce = f"otacon-wildcard-{secrets.token_hex(8)}.com"
        ips = frozenset(await self._resolve_a(nonce))
        if ips:
            _log.debug("NXDOMAIN hijack detected: %s resolved to %s", nonce, sorted(ips))
        return ips

    async def _wildcard_ips(self) -> frozenset[str]:
        if self._wildcard_task is None:
            self._wildcard_task = asyncio.create_task(self._probe_wildcard())
        return await self._wildcard_task

    @property
    def target_title(self) -> str | None:
        return self._target_title

    @property
    def target_favicon_hash(self) -> int | None:
        return self._target_favicon_hash

    @property
    def dns_hijack_detected(self) -> bool:
        t = self._wildcard_task
        return bool(t is not None and t.done() and not t.cancelled() and t.result())

    async def _resolve_mx(self, domain: str) -> list[str]:
        """Mail exchanges for *domain*, with a null MX spelled as it is published.

        c-ares hands back an empty exchange for RFC 7505's ``MX 0 .``; keeping
        it as ``NULL_MX`` lets the caller tell "no mail by declaration" from
        "a mail server is configured".
        """
        return [_strip_unsafe_chars(r.host) or NULL_MX for r in await self._query(domain, "MX")]

    async def _resolve_ns(self, domain: str) -> list[str]:
        return [_strip_unsafe_chars(r.host).lower() for r in await self._query(domain, "NS")]

    async def _check_dnsbl(self, domain: str) -> tuple[bool, str | None]:
        listed, source, refused = await check_dnsbl(domain, self._dns, timeout=_DNS_TIMEOUT)
        if refused:
            # Sticky for the whole scan: one refusal means the list is not
            # answering this host, so the report must not read as a clean bill.
            self.dnsbl_refused = True
        return listed, source

    async def _resolve_txt(self, domain: str) -> list[str]:
        out: list[str] = []
        for r in await self._query(domain, "TXT"):
            txt = getattr(r, "text", "")
            if isinstance(txt, bytes):
                txt = txt.decode("utf-8", "replace")
            out.append(str(txt))
        return out

    async def _check_email_security(
        self, domain: str
    ) -> tuple[bool, str | None, bool, str | None, bool]:
        return await check_email_security(domain, self._resolve_txt)

    async def _check_ssl(
        self, domain: str, ip: str
    ) -> tuple[bool, str | None, int | None, bool | None]:
        return await probe_ssl(domain, ip, timeout=_HTTP_TIMEOUT, tls_sem=self._tls_sem)

    @staticmethod
    def _inspect_cert(ssl_obj: Any, domain: str) -> tuple[str | None, int | None, bool | None]:
        return inspect_cert(ssl_obj, domain)

    @staticmethod
    async def _read_capped(resp: httpx.Response) -> str:
        return await read_capped_body(resp)

    async def _probe_http(self, domain: str) -> HTTPProbeResult:
        if self._http is None:
            raise RuntimeError("Resolver._probe_http called outside async context manager")
        return await probe_http(domain, self._http, deadline=_HTTP_DEADLINE, grace=_HTTPS_GRACE)

    async def _probe(
        self, domain: str, ips: list[str]
    ) -> tuple[tuple[bool, str | None, int | None, bool | None], HTTPProbeResult]:
        safe_ip = first_safe_ip(ips)
        if safe_ip is None:
            if ips:
                _log.debug(
                    "skipping HTTP/SSL probe for %s: no non-internal IP among %s",
                    domain,
                    ips,
                )
            return (False, None, None, None), HTTPProbeResult(None, None, None, None, False, None)

        self._ip_pins[domain] = safe_ip
        async with asyncio.TaskGroup() as tg:
            t_ssl = tg.create_task(self._check_ssl(domain, safe_ip))
            t_http = tg.create_task(self._probe_http(domain))
        ssl_info = t_ssl.result()
        http_res = t_http.result()
        if not isinstance(http_res, HTTPProbeResult):
            http_res = HTTPProbeResult(
                http_res[0],
                http_res[1],
                http_res[2],
                http_res[3],
                getattr(http_res, "has_login_form", False),
                getattr(http_res, "favicon_hash", None),
            )
        return ssl_info, http_res

    async def _fetch_whois(self, domain: str) -> tuple[datetime | None, int | None]:
        async with self._whois_sem:
            return await fetch_domain_age(domain, client=self._rdap)

    async def check_one(self, perm: Permutation) -> DomainResult:
        """Fully checks a single domain permutation variant against network signals."""
        async with self._sem:
            try:
                async with asyncio.TaskGroup() as tg:
                    t_ips = tg.create_task(self._resolve_a(perm.domain))
                    t_mx = tg.create_task(self._resolve_mx(perm.domain))
                ips = t_ips.result()
                mx = t_mx.result()

                if ips:
                    wildcard = await self._wildcard_ips()
                    if wildcard and set(ips) <= wildcard:
                        _log.debug("ignoring hijacked answer for %s: %s", perm.domain, ips)
                        ips = []

                resolves = bool(ips)
                # A null MX proves somebody registered the name, but declares
                # it handles no mail — it must not score as a phishing mailbox.
                has_mx = any(exchange != NULL_MX for exchange in mx)

                has_ssl = False
                ssl_issuer: str | None = None
                ssl_cert_age_days: int | None = None
                ssl_san_matches: bool | None = None
                http_status: int | None = None
                server_header: str | None = None
                redirects_to: str | None = None
                page_title: str | None = None
                has_login_form = False
                favicon_hash: int | None = None
                favicon_matches_target = False

                if resolves and self._check_http:
                    (
                        (ssl_ok, issuer, cert_age, san_match),
                        http_res,
                    ) = await self._probe(perm.domain, ips)
                    has_ssl = ssl_ok
                    ssl_issuer = issuer
                    ssl_cert_age_days = cert_age
                    ssl_san_matches = san_match
                    http_status = http_res[0]
                    server_header = http_res[1]
                    redirects_to = http_res[2]
                    page_title = http_res[3]
                    has_login_form = getattr(http_res, "has_login_form", False)
                    favicon_hash = getattr(http_res, "favicon_hash", None)
                    if favicon_hash is not None and self._target_favicon_hash is not None:
                        favicon_matches_target = favicon_hash == self._target_favicon_hash

                is_registered = resolves or bool(mx) or has_ssl

                ns_records: list[str] = []
                created_at: datetime | None = None
                age_days: int | None = None
                dnsbl_listed = False
                dnsbl_source: str | None = None
                has_spf = False
                spf_record: str | None = None
                has_dmarc = False
                dmarc_policy: str | None = None
                is_mail_spoofable = False

                if is_registered:
                    t_whois = None
                    t_dnsbl = None
                    t_email = None
                    async with asyncio.TaskGroup() as tg:
                        t_ns = tg.create_task(self._resolve_ns(perm.domain))
                        if self._check_whois:
                            t_whois = tg.create_task(self._fetch_whois(perm.domain))
                        if self._enable_dnsbl:
                            t_dnsbl = tg.create_task(self._check_dnsbl(perm.domain))
                        if has_mx:
                            t_email = tg.create_task(self._check_email_security(perm.domain))

                    ns_records = t_ns.result()
                    if t_whois is not None:
                        created_at, age_days = t_whois.result()
                    if t_dnsbl is not None:
                        dnsbl_listed, dnsbl_source = t_dnsbl.result()
                    if t_email is not None:
                        (
                            has_spf,
                            spf_record,
                            has_dmarc,
                            dmarc_policy,
                            is_mail_spoofable,
                        ) = t_email.result()

                return DomainResult(
                    domain=perm.domain,
                    kind=perm.kind,
                    note=perm.note,
                    resolves=resolves,
                    ip_addresses=ips,
                    has_mx=has_mx,
                    mx_records=mx,
                    has_ssl=has_ssl,
                    ssl_issuer=ssl_issuer,
                    ssl_cert_age_days=ssl_cert_age_days,
                    ssl_san_matches=ssl_san_matches,
                    http_status=http_status,
                    server_header=server_header,
                    redirects_to=redirects_to,
                    page_title=page_title,
                    ns_records=ns_records,
                    created_at=created_at,
                    age_days=age_days,
                    dnsbl_listed=dnsbl_listed,
                    dnsbl_source=dnsbl_source,
                    has_spf=has_spf,
                    spf_record=spf_record,
                    has_dmarc=has_dmarc,
                    dmarc_policy=dmarc_policy,
                    is_mail_spoofable=is_mail_spoofable,
                    favicon_hash=favicon_hash,
                    favicon_matches_target=favicon_matches_target,
                    has_login_form=has_login_form,
                )
            except Exception as exc:
                self.probe_failures += 1
                _log.debug("check_one failed for %s: %r", perm.domain, exc)
                return DomainResult(domain=perm.domain, kind=perm.kind, note=perm.note)


__all__ = [
    "DEFAULT_CONCURRENCY",
    "_DNS_TIMEOUT",
    "_HTTPS_GRACE",
    "_HTTPS_PORT",
    "_HTTP_DEADLINE",
    "_HTTP_TIMEOUT",
    "_MAX_BODY_BYTES",
    "_REDIRECT_MAX",
    "Resolver",
]
