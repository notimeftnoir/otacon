"""Immutable domain entities and core representations for Otacon.

Uses frozen slots dataclasses for maximum performance and minimal memory footprint.
Boundary serialization and deserialization are handled by Pydantic V2 schemas.
"""

from __future__ import annotations

import dataclasses
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Self

from .schemas import DomainResultSchema, PermutationSchema, ScanReportSchema
from .types import PermutationType, RiskLevel


@dataclass(frozen=True, slots=True)
class Permutation:
    """A generated lookalike domain variant before network probing."""

    domain: str
    kind: PermutationType
    note: str = ""

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)

    def model_dump_json(self, indent: int | None = None) -> str:
        return PermutationSchema.model_validate(asdict(self)).model_dump_json(indent=indent)

    def model_copy(self, *, update: dict[str, Any] | None = None) -> Self:
        return dataclasses.replace(self, **(update or {}))

    @classmethod
    def model_validate(cls, data: Any) -> Self:
        schema = PermutationSchema.model_validate(data)
        return cls(domain=schema.domain, kind=schema.kind, note=schema.note)

    @classmethod
    def model_validate_json(cls, data: str) -> Self:
        schema = PermutationSchema.model_validate_json(data)
        return cls(domain=schema.domain, kind=schema.kind, note=schema.note)


@dataclass(frozen=True, slots=True)
class NetworkSignals:
    """Network indicators collected during resolution and probe stages."""

    resolves: bool = False
    ip_addresses: list[str] = field(default_factory=list)
    has_mx: bool = False
    mx_records: list[str] = field(default_factory=list)
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
    ns_records: list[str] = field(default_factory=list)
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


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Calculated risk heuristic indicators."""

    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE
    risk_reasons: list[str] = field(default_factory=list)
    is_likely_defensive: bool = False
    is_parked: bool = False


@dataclass(slots=True)
class DomainResult:
    """The complete result of checking one domain variant against the network."""

    domain: str
    kind: PermutationType
    note: str = ""

    resolves: bool = False
    ip_addresses: list[str] = field(default_factory=list)
    has_mx: bool = False
    mx_records: list[str] = field(default_factory=list)
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

    ns_records: list[str] = field(default_factory=list)

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
    risk_reasons: list[str] = field(default_factory=list)
    is_likely_defensive: bool = False
    is_parked: bool = False

    @property
    def is_registered(self) -> bool:
        """Whether the variant looks actively registered or in use."""
        return self.resolves or self.has_mx or self.has_ssl

    def model_copy(self, *, update: dict[str, Any] | None = None) -> Self:
        """Returns a copy of this result with updated attributes."""
        return dataclasses.replace(self, **(update or {}))

    def model_dump(self) -> dict[str, Any]:
        """Serializes the result into a plain dictionary."""
        return DomainResultSchema.model_validate(asdict(self)).model_dump(mode="python")

    def model_dump_json(self, indent: int | None = None) -> str:
        """Serializes the result into a JSON string."""
        return DomainResultSchema.model_validate(asdict(self)).model_dump_json(indent=indent)

    @classmethod
    def model_validate(cls, data: Any) -> Self:
        """Validates input through Pydantic schema and returns an immutable DomainResult."""
        schema = DomainResultSchema.model_validate(data)
        return cls(**schema.model_dump())

    @classmethod
    def model_validate_json(cls, data: str) -> Self:
        """Validates JSON input through Pydantic schema and returns an immutable DomainResult."""
        schema = DomainResultSchema.model_validate_json(data)
        return cls(**schema.model_dump())


@dataclass(slots=True)
class ScanReport:
    """Complete scan report container."""

    target: str
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    total_permutations: int = 0
    results: list[DomainResult] = field(default_factory=list)
    dns_hijack_detected: bool = False

    @property
    def registered(self) -> list[DomainResult]:
        """Registered variants found during the scan."""
        return [r for r in self.results if r.is_registered]

    @property
    def threats(self) -> list[DomainResult]:
        """Elevated-risk variants sorted descending by risk score."""
        flagged = [r for r in self.results if r.risk_level != RiskLevel.SAFE]
        return sorted(flagged, key=lambda r: r.risk_score, reverse=True)

    def model_copy(self, *, update: dict[str, Any] | None = None) -> Self:
        """Returns a copy of this report with updated attributes."""
        return dataclasses.replace(self, **(update or {}))

    def model_dump(self) -> dict[str, Any]:
        """Serializes the report into a plain dictionary."""
        return ScanReportSchema.model_validate(asdict(self)).model_dump(mode="python")

    def model_dump_json(self, indent: int | None = None) -> str:
        """Serializes the report into a JSON string."""
        return ScanReportSchema.model_validate(asdict(self)).model_dump_json(indent=indent)

    @classmethod
    def model_validate(cls, data: Any) -> Self:
        """Validates input through Pydantic schema and returns an immutable ScanReport."""
        schema = ScanReportSchema.model_validate(data)
        raw = schema.model_dump()
        raw_results = raw.pop("results", [])
        results = [DomainResult(**r) for r in raw_results]
        return cls(results=results, **raw)

    @classmethod
    def model_validate_json(cls, data: str) -> Self:
        """Validates JSON input through Pydantic schema and returns an immutable ScanReport."""
        schema = ScanReportSchema.model_validate_json(data)
        raw = schema.model_dump()
        raw_results = raw.pop("results", [])
        results = [DomainResult(**r) for r in raw_results]
        return cls(results=results, **raw)
