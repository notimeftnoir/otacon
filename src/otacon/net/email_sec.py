"""Email security posture: SPF and DMARC record inspection."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from .content import _strip_unsafe_chars

_DMARC_POLICY_RE = re.compile(r"\bp=([a-z]+)")


async def check_email_security(
    domain: str,
    resolve_txt_func: Any,
) -> tuple[bool, str | None, bool, str | None, bool]:
    """Inspects SPF and DMARC policies for domain.

    Returns (has_spf, spf_rec, has_dmarc, dmarc_policy, is_spoofable).
    """
    txt_records, dmarc_records = await asyncio.gather(
        resolve_txt_func(domain),
        resolve_txt_func(f"_dmarc.{domain}"),
    )

    has_spf = False
    spf_rec: str | None = None
    for txt in txt_records:
        if "v=spf1" in txt.lower():
            has_spf = True
            # Whatever the remote zone published; sanitised like MX and NS are.
            spf_rec = _strip_unsafe_chars(txt.strip())
            break

    has_dmarc = False
    dmarc_policy: str | None = None
    for txt in dmarc_records:
        txt_lower = txt.lower()
        if "v=dmarc1" in txt_lower:
            has_dmarc = True
            m = _DMARC_POLICY_RE.search(txt_lower)
            if m:
                dmarc_policy = m.group(1)
            break

    # Domain is spoofable if DMARC is absent or configured with p=none
    is_spoofable = (not has_dmarc) or (dmarc_policy == "none")
    return has_spf, spf_rec, has_dmarc, dmarc_policy, is_spoofable


__all__ = ["check_email_security"]
