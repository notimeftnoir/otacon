"""Compatibility shim for risk scoring in otacon v2.0."""

from __future__ import annotations

from .scoring.classifiers import (
    is_defensive,
    is_parked,
    is_sinkhole,
)
from .scoring.config import (
    ScoringWeights,
)
from .scoring.engine import (
    AGE_FRESH_DAYS,
    AGE_NEW_DAYS,
    AGE_RECENT_DAYS,
    _title_similarity,
    count_fresh,
    get_age_fresh_days,
    get_age_new_days,
    score,
)

__all__ = [
    "AGE_FRESH_DAYS",
    "AGE_NEW_DAYS",
    "AGE_RECENT_DAYS",
    "ScoringWeights",
    "_title_similarity",
    "count_fresh",
    "get_age_fresh_days",
    "get_age_new_days",
    "is_defensive",
    "is_parked",
    "is_sinkhole",
    "score",
]
