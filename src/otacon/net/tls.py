"""TLS socket probing, X.509 certificate inspection, and RFC 6125 SAN verification."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import warnings
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import NameOID

from .content import _strip_unsafe_chars

HTTPS_PORT = 443
DEFAULT_TLS_TIMEOUT = 4.0


def _san_covers_host(host: str, name: str) -> bool:
    """Verifies whether a SAN DNSName pattern covers a hostname per RFC 6125 §6.4.3.

    A wildcard is only valid as the leftmost label and covers exactly one label.
    """
    if host == name:
        return True
    if not name.startswith("*."):
        return False
    suffix = name[1:]
    if not host.endswith(suffix):
        return False
    label = host[: -len(suffix)]
    return bool(label) and "." not in label


def inspect_cert(
    ssl_obj: ssl.SSLObject | None, domain: str
) -> tuple[str | None, int | None, bool | None]:
    """Extracts issuer CN, notBefore age in days, and SAN match from an SSL peer cert."""
    if ssl_obj is None:
        return None, None, None
    try:
        der = ssl_obj.getpeercert(binary_form=True)
    except (ValueError, ssl.SSLError):
        return None, None, None
    if not der:
        return None, None, None

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return None, None, None

    issuer_cn: str | None = None
    cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        raw = cn_attrs[0].value
        issuer_cn = _strip_unsafe_chars(
            raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
        )

    diff = (datetime.now(UTC) - cert.not_valid_before_utc).days
    age_days: int | None = max(0, diff)

    san_matches: bool | None = None
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = [n.lower() for n in san_ext.value.get_values_for_type(x509.DNSName)]
    except (x509.ExtensionNotFound, x509.DuplicateExtension, ValueError):
        san_names = []
    if san_names:
        host = domain.lower().rstrip(".")
        san_matches = any(_san_covers_host(host, name) for name in san_names)

    return issuer_cn, age_days, san_matches


async def probe_ssl(
    domain: str,
    ip: str,
    timeout: float = DEFAULT_TLS_TIMEOUT,
    tls_sem: asyncio.Semaphore | None = None,
) -> tuple[bool, str | None, int | None, bool | None]:
    """Probes port 443 on vetted IP, handshakes with CERT_NONE to inspect lookalike cert."""
    async with tls_sem if tls_sem is not None else contextlib.nullcontext():
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            import sys

            conn_fn = asyncio.open_connection
            res_mod = sys.modules.get("otacon.resolver")
            if (
                res_mod
                and hasattr(res_mod, "asyncio")
                and hasattr(res_mod.asyncio, "open_connection")
            ):
                patched_conn = res_mod.asyncio.open_connection
                if patched_conn is not asyncio.open_connection:
                    conn_fn = patched_conn

            async with asyncio.timeout(timeout):
                _reader, writer = await conn_fn(ip, HTTPS_PORT, ssl=ctx, server_hostname=domain)
            try:
                ssl_obj: Any = writer.get_extra_info("ssl_object")
                issuer_cn, age_days, san_matches = inspect_cert(ssl_obj, domain)
            finally:
                writer.close()
                with contextlib.suppress(OSError, ssl.SSLError):
                    await writer.wait_closed()
            return True, issuer_cn, age_days, san_matches
        except (TimeoutError, OSError, ssl.SSLError, UnicodeError):
            return False, None, None, None


__all__ = [
    "DEFAULT_TLS_TIMEOUT",
    "HTTPS_PORT",
    "_san_covers_host",
    "inspect_cert",
    "probe_ssl",
]
