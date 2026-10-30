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

# Share of failed DNS lookups above which a scan's quiet result is not
# trustworthy. Set well clear of the handful of timeouts a busy scan sees on a
# normal network, and far below the near-total failure a broken resolver gives.
DEGRADED_RATIO = 0.2


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
        """Whether the variant looks actively registered or in use.

        ``mx_records`` is checked as well as ``has_mx``: a domain whose only
        record is RFC 7505's null MX handles no mail, so ``has_mx`` is False,
        but somebody had to register the name to publish it.
        """
        return self.resolves or self.has_mx or self.has_ssl or bool(self.mx_records)

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


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Which probes a scan actually ran.

    "No MX record" and "MX was never checked" produce the same empty field, so
    a report that does not say what it looked at cannot be compared against
    another. Defaults are True so a report stored before this existed reads
    exactly as it did before.
    """

    http: bool = True
    whois: bool = True
    dnsbl: bool = True
    ct: bool = True


def _report_fields(schema: ScanReportSchema) -> dict[str, Any]:
    """Unpacks a validated report schema into ScanReport's own constructor kwargs."""
    raw = schema.model_dump()
    raw.pop("degraded", None)  # derived from the counters, never trusted from disk
    raw["results"] = [DomainResult(**r) for r in raw.pop("results", [])]
    raw["options"] = ScanOptions(**raw.pop("options", {}))
    return raw


@dataclass(slots=True)
class ScanReport:
    """Complete scan report container."""

    target: str
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    total_permutations: int = 0
    results: list[DomainResult] = field(default_factory=list)
    dns_hijack_detected: bool = False
    dns_queries: int = 0
    dns_failures: int = 0
    probe_failures: int = 0
    """Variants whose probe raised instead of answering. See ``degraded``."""
    dnsbl_refused: bool = False
    """True when a reputation list declined to answer rather than saying clean.

    Spamhaus refuses queries arriving via large public resolvers. Scored as
    "not listed" that silently zeroed the heaviest weight in the scoring, so
    the fact travels with the report.
    """
    options: ScanOptions = field(default_factory=ScanOptions)

    @property
    def dns_failure_ratio(self) -> float:
        """Share of DNS lookups that failed rather than answering."""
        return self.dns_failures / self.dns_queries if self.dns_queries else 0.0

    @property
    def probe_failure_ratio(self) -> float:
        """Share of variants whose probe raised instead of answering."""
        checked = len(self.results)
        return self.probe_failures / checked if checked else 0.0

    @property
    def degraded(self) -> bool:
        """True when enough lookups failed that a quiet result is not trustworthy.

        "Does not resolve" and "could not be checked" produce the same empty
        result, so a scan whose resolver is broken reports an all-clear. Probe
        failures count for the same reason: a variant whose check raised comes
        back blank, which reads as "nothing registered here". Above this share,
        the verdict says so instead.
        """
        return (self.dns_queries > 0 and self.dns_failure_ratio >= DEGRADED_RATIO) or (
            bool(self.results) and self.probe_failure_ratio >= DEGRADED_RATIO
        )

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

    def _schema(self) -> ScanReportSchema:
        # `degraded` is a property, so asdict() leaves it out; a JSON consumer
        # (a CI job, a SIEM) should not have to re-derive it from the counters.
        return ScanReportSchema.model_validate({**asdict(self), "degraded": self.degraded})

    def model_dump(self) -> dict[str, Any]:
        """Serializes the report into a plain dictionary."""
        return self._schema().model_dump(mode="python")

    def model_dump_json(self, indent: int | None = None) -> str:
        """Serializes the report into a JSON string."""
        return self._schema().model_dump_json(indent=indent)

    @classmethod
    def model_validate(cls, data: Any) -> Self:
        """Validates input through Pydantic schema and returns an immutable ScanReport."""
        return cls(**_report_fields(ScanReportSchema.model_validate(data)))

    @classmethod
    def model_validate_json(cls, data: str) -> Self:
        """Validates JSON input through Pydantic schema and returns an immutable ScanReport."""
        return cls(**_report_fields(ScanReportSchema.model_validate_json(data)))
