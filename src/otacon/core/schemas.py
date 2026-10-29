"""Pydantic V2 schemas for external boundary validation and I/O serialization."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from .types import PermutationType, RiskLevel


class PermutationSchema(BaseModel):
    """Schema for a single generated permutation variant at the boundary."""

    model_config = ConfigDict(extra="ignore")

    domain: Annotated[str, Field(min_length=1, max_length=253)]
    kind: PermutationType
    note: str = ""


class DomainResultSchema(BaseModel):
    """Schema for a domain probe result at external boundaries (JSON export/import)."""

    model_config = ConfigDict(extra="ignore")

    domain: str
    kind: PermutationType
    note: str = ""

    resolves: bool = False
    ip_addresses: list[str] = Field(default_factory=list)
    has_mx: bool = False
    mx_records: list[str] = Field(default_factory=list)
    has_ssl: bool = False
    ssl_issuer: str | None = None
    ssl_cert_age_days: int | None = None
    ssl_san_matches: bool | None = None
    http_status: int | None = None
    server_header: str | None = None
    redirects_to: str | None = None

    page_title: str | None = None
    title_similarity: float | None = None

    created_at: datetime | None = None
    age_days: int | None = None

    ns_records: list[str] = Field(default_factory=list)

    has_spf: bool = False
    spf_record: str | None = None
    has_dmarc: bool = False
    dmarc_policy: str | None = None
    is_mail_spoofable: bool = False

    favicon_hash: int | None = None
    favicon_matches_target: bool = False
    has_login_form: bool = False

    dnsbl_listed: bool = False
    dnsbl_source: str | None = None
    is_sinkhole: bool = False

    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE
    risk_reasons: list[str] = Field(default_factory=list)
    is_likely_defensive: bool = False
    is_parked: bool = False


class ScanReportSchema(BaseModel):
    """Complete scan report schema used for JSON file exports and imports."""

    model_config = ConfigDict(extra="ignore")

    target: str
    started_at: datetime
    total_permutations: int = 0
    results: list[DomainResultSchema] = Field(default_factory=list)
    dns_hijack_detected: bool = False
    dns_queries: int = 0
    dns_failures: int = 0
    cancelled: bool = False


class ScoringWeightsSchema(BaseModel):
    """Configurable scoring weights validated at input boundaries."""

    model_config = ConfigDict(extra="ignore")

    points_homoglyph: int = 35
    points_idn: int = 35
    points_typo: int = 18
    points_combo: int = 20
    points_bitsquat: int = 15
    points_subdomain: int = 30
    points_soundsquat: int = 15
    points_vowel_swap: int = 15
    points_plural: int = 12
    points_www_merge: int = 25
    points_hyphen: int = 10
    points_tld_swap: int = 8
    points_ct_log: int = 20

    points_resolves: int = 10
    points_mx: int = 15
    points_ssl: int = 10
    points_http_2xx: int = 15
    points_http_3xx: int = 10
    points_http_4xx: int = 5
    points_san_mismatch: int = 20
    points_fresh_cert: int = 25
    points_external_redirect: int = 15
    points_age_new: int = 25
    points_age_recent: int = 12

    points_cloned_favicon: int = 30
    points_login_form: int = 25
    points_dnsbl: int = 40
    points_spoofable_email: int = 15


class WhoisResultSchema(BaseModel):
    """Boundary schema for parsed RDAP/WHOIS response data."""

    model_config = ConfigDict(extra="ignore")

    created_at: datetime | None = None
    age_days: int | None = None
    raw_text: str | None = None


class CTLogEntrySchema(BaseModel):
    """Boundary schema for Certificate Transparency log discovery records."""

    model_config = ConfigDict(extra="ignore")

    domain: str
    issuer: str | None = None
    not_before: datetime | None = None
