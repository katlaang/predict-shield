"""Offline verification feedback cycle connecting scheduler and independent assessment.

This is a decision/recording adapter, not a live verification probe executor.
Only a valid independently assessed VERIFIED result updates last_verified_at.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Iterable

from .assessment import Assessment, Evidence, Outcome, assess
from .reverification import ProbeRequest, Subject, schedule


@dataclass(frozen=True)
class TrackedControl:
    subject_id: str
    asset: str
    assertion: str
    last_verified_at: int
    risk: float
    changed_at: int | None = None
    probe_units: int = 1

    def subject(self) -> Subject:
        return Subject(self.subject_id, self.last_verified_at, self.risk,
                       self.changed_at, self.probe_units)


@dataclass(frozen=True)
class VerificationRecord:
    subject_id: str
    observed_at: int
    outcome: Outcome
    reason: str
    evidence_sources: tuple[str, ...]
    conflicting_evidence: bool


def select_probes(controls: Iterable[TrackedControl], *, now: int,
                  budget: int, policy: str, interval: int = 60,
                  high_risk_after: int = 15,
                  high_risk_cutoff: float = 0.7) -> list[ProbeRequest]:
    """Schedule checks using only operator-visible input state."""
    entries = list(controls)
    if len({c.subject_id for c in entries}) != len(entries):
        raise ValueError("duplicate subject_id")
    return schedule([c.subject() for c in entries], now=now, budget=budget,
                    policy=policy, interval=interval,
                    high_risk_after=high_risk_after,
                    high_risk_cutoff=high_risk_cutoff)


def record_probe(control: TrackedControl, request: ProbeRequest,
                 evidence: list[Evidence], *, observed_at: int,
                 requested_at: int,
                 max_age_seconds: int = 3600,
                 required_independent_checks: int = 1
                 ) -> tuple[TrackedControl, VerificationRecord]:
    """Evaluate evidence after a requested probe, never manufacture success.

    Evidence is supplied by a separate observer. This adapter cannot collect
    it, and the caller remains responsible for authenticating and recording it.
    """
    if request.subject_id != control.subject_id:
        raise ValueError("probe request does not match tracked subject")
    if (requested_at < control.last_verified_at or requested_at > observed_at
            or observed_at < 0):
        raise ValueError("invalid probe request or observation order")
    observed_dt = datetime.fromtimestamp(observed_at, tz=timezone.utc)
    result: Assessment = assess(
        control.asset, control.assertion, evidence,
        required_independent_checks=required_independent_checks,
        max_age_seconds=max_age_seconds, now=observed_dt)
    # A control changed after this request began. Even a successful old-scope
    # probe cannot clear or supersede the newer change.
    if (control.changed_at is not None and
            requested_at < control.changed_at <= observed_at):
        result = Assessment(Outcome.INDETERMINATE, result.conflicting_evidence,
                            "Control changed after probe request; fresh check required.",
                            result.evidence_sources)
    # Important: NOT VERIFIED/INDETERMINATE/NOT APPLICABLE are not positive
    # evidence and must never advance the last known successful verification.
    updated = replace(control, last_verified_at=observed_at,
                      changed_at=None) if result.outcome is Outcome.VERIFIED else control
    record = VerificationRecord(control.subject_id, observed_at, result.outcome,
                                result.reason, result.evidence_sources,
                                result.conflicting_evidence)
    return updated, record
