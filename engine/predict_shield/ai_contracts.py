"""Typed prediction and outcome records for PREDICT-SHIELD v2.2.

Research interfaces only. Predictions cannot authorize an action or establish
verification. An oracle label is an experiment-only record, never model input.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from math import isfinite
from typing import Protocol


class VerificationOutcome(str, Enum):
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT VERIFIED"
    INDETERMINATE = "INDETERMINATE"
    NOT_APPLICABLE = "NOT APPLICABLE"


class ActionTier(str, Enum):
    AUTOMATIC = "AUTOMATIC"
    APPROVAL = "APPROVAL"
    PROHIBITED = "PROHIBITED"


@dataclass(frozen=True)
class Interval:
    lower: float
    estimate: float
    upper: float

    def __post_init__(self) -> None:
        if not all(isfinite(v) for v in (self.lower, self.estimate, self.upper)):
            raise ValueError("Interval values must be finite")
        if not self.lower <= self.estimate <= self.upper:
            raise ValueError("Intervals must be ordered")


@dataclass(frozen=True)
class EvidenceSnapshot:
    snapshot_id: str
    case_id: str
    captured_at: datetime
    source_ids: tuple[str, ...]
    trusted: bool
    scope_complete: bool

    def __post_init__(self) -> None:
        if not self.snapshot_id or not self.case_id:
            raise ValueError("Evidence requires snapshot and case IDs")
        if self.captured_at.tzinfo is None:
            raise ValueError("Evidence timestamp must be timezone-aware")


@dataclass(frozen=True)
class CandidateAction:
    action_id: str
    tier: ActionTier
    affected_services: tuple[str, ...]
    postcondition: str
    reversible: bool = False


@dataclass(frozen=True)
class ActionPrediction:
    action_id: str
    snapshot_id: str
    model_name: str
    model_version: str
    predicted_at: datetime
    residual_risk: Interval
    # error counts or equivalent service-budget units for the same accounting window
    additional_errors: dict[str, Interval]
    out_of_distribution: bool = False
    calibration_supported: bool = False
    training_fingerprint: str = ""

    def __post_init__(self) -> None:
        if self.predicted_at.tzinfo is None:
            raise ValueError("Prediction timestamp must be timezone-aware")
        if not (0.0 <= self.residual_risk.lower <= self.residual_risk.upper <= 1.0):
            raise ValueError("Residual risk must be normalized to [0, 1]")
        if any(v.lower < 0 for v in self.additional_errors.values()):
            raise ValueError("Additional error counts cannot be negative")


@dataclass(frozen=True)
class PreActionPredictionRecord:
    run_id: str
    case_id: str
    condition_group: str
    snapshot_id: str
    prediction: ActionPrediction


@dataclass(frozen=True)
class VerificationRecord:
    run_id: str
    case_id: str
    assertion_id: str
    outcome: VerificationOutcome
    observation_ids: tuple[str, ...]
    scope_complete: bool
    assessed_at: datetime


@dataclass(frozen=True)
class OracleRecord:
    run_id: str
    case_id: str
    assertion_id: str
    applicable: bool | None
    actual_holds: bool | None
    observed_at: datetime
    # This record is forbidden as an input to LearnedActionEstimator.predict.
    oracle_method: str


@dataclass(frozen=True)
class ServiceHealth:
    service_id: str
    additional_failed_or_late_requests: int | None
    latency_p95_ms: float | None
    observation_complete: bool


@dataclass(frozen=True)
class OperationalOutcomeRecord:
    run_id: str
    case_id: str
    action_id: str
    measured_at: datetime
    residual_exposure_fraction: float | None
    service_health: tuple[ServiceHealth, ...]


class LearnedActionEstimator(Protocol):
    def predict(
        self, snapshot: EvidenceSnapshot,
        actions: tuple[CandidateAction, ...],
    ) -> tuple[ActionPrediction, ...]:
        """Predict from PRE-action information only; never read OracleRecord."""
        ...


@dataclass(frozen=True)
class TrainingExampleLink:
    """References four *distinct* record types without conflating their semantics."""
    run_id: str
    case_id: str
    prediction_record_id: str
    verification_record_id: str | None
    oracle_record_id: str | None
    operational_outcome_record_id: str | None
    split_group: str
    split: str  # train / calibration / test
    label_observed: bool
    event_censored: bool | None = None

    def __post_init__(self) -> None:
        if self.split not in ("train", "calibration", "test"):
            raise ValueError("Invalid dataset split")
        if not self.run_id or not self.split_group or not self.prediction_record_id:
            raise ValueError("Missing training-record provenance")
