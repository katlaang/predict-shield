"""Intrusion-informed containment: "a new input to Assess: authorized
detections" (the framework design white paper's Phase 2 extension point).

Detection engineering (writing or generating rules for a SIEM, scoring
MITRE ATT&CK coverage) is a different problem from what this module does,
and this module does not do it. There is no rule generator here. What this
module does is narrower and matches what the design actually specifies:
decide whether an inbound detection alert, produced by a tool this pipeline
does not control, is admissible as evidence at all, and if so, raise the
urgency of the assertion it concerns using the mechanisms this pipeline
already has (`assessment.assess`, the re-verification scheduler), rather
than inventing new ones.

A detection alert is treated exactly like advisory text and threat feeds
elsewhere in this pipeline: untrusted by default. It is admitted only from
a source the operator registered ahead of time, following the same
fail-closed pattern `exploit_confirmation.py` already uses for registered
HTTP signatures:

    * A detection is only ever admitted if its source tool is in the
      operator's registered catalog ahead of time, and that source is
      marked trusted. An unregistered or untrusted source is rejected
      before anything else runs.
    * A detection with a confidence outside [0,1], a missing technique
      identifier, or a timestamp in the future relative to `now` is
      rejected outright, not silently clamped or defaulted.
    * A stale detection (older than `max_age_seconds`) is rejected:
      urgency only ever comes from a current signal, the same freshness
      rule `assessment.assess` already enforces for every other assertion.
    * Admission produces an `AdmissionResult` (carrying the `Evidence` for
      the existing `assessment.assess()` pipeline) and that result, not a
      raw `DetectionEvent`, is the only thing `to_reverification_subject_
      update()` accepts: a detection that never went through `admit()`
      cannot raise a subject's priority, enforced at runtime, not only by
      type hint. It never itself approves, executes, or verifies an
      action, and it does not change what counts as VERIFIED: a
      conflicting independent check can still outvote an admitted
      detection exactly as today.

What this module does NOT yet do, honestly: it does not tighten the policy
gate's own response deadlines or raise an action's approval tier based on
detection confidence. The framework design lists that as a still-open
requirement for this extension, not something already reused from the
core, and nothing here claims otherwise.

A second, separate gap: `admit()` checks that `source_id` names a
registered, trusted source, which is a policy check, not an authentication
check. Nothing here verifies that a detection actually originated from the
source it claims, the way `exploit_confirmation.py` verifies a signature
by probing the authorized host live. Until a transport-level authentication
mechanism (for example a signed webhook or mTLS) is added at the point
where detections enter this pipeline, a party who can submit a
`DetectionEvent` at all can claim any registered `source_id`, and
`independent=True` on the resulting `Evidence` should be read as "from a
distinct, policy-approved channel," not as "independently authenticated."
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from math import isfinite

from .assessment import Evidence
from .reverification import Subject

SOURCE_PREFIX = "detection:"


@dataclass(frozen=True)
class RegisteredDetectionSource:
    """A detection tool (SIEM, EDR, IDS) the operator has registered ahead
    of time. A detection from any other source_id is never admitted."""

    source_id: str
    name: str
    trusted: bool = True

    def validate(self) -> None:
        if not self.source_id:
            raise ValueError("source_id required")
        if not self.name:
            raise ValueError("name required")


@dataclass(frozen=True)
class DetectionEvent:
    """An inbound, untrusted claim that something is happening on `asset`.
    Nothing here is taken on faith: `admit()` checks it against the
    operator's registered source catalog, and against its own internal
    consistency, before it becomes evidence of anything."""

    detection_id: str
    asset: str
    source_id: str
    technique: str
    confidence: float
    observed_at: datetime

    def _validate(self, now: datetime) -> None:
        if not self.detection_id or not self.asset or not self.source_id:
            raise ValueError("detection_id, asset and source_id are required")
        if not self.technique:
            raise ValueError("technique is required: an ungrounded detection cannot be admitted")
        if not isfinite(self.confidence) or not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be finite in [0,1]")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.observed_at > now:
            raise ValueError("observed_at is in the future: look-ahead detections are rejected")


@dataclass(frozen=True)
class AdmissionResult:
    """Proof that a `DetectionEvent` passed `admit()`'s checks. This is the
    only object `to_reverification_subject_update()` accepts, and the only
    way to construct one is to call `admit()` successfully: a detection
    that was never admitted cannot reach the scheduler, by construction,
    not merely by convention."""

    evidence: Evidence
    asset: str
    confidence: float


def admit(detection: DetectionEvent, registry: dict[str, RegisteredDetectionSource], *,
          now: datetime | None = None, max_age_seconds: float = 900.0) -> AdmissionResult:
    """Admit a detection only from a registered, trusted, current, and
    well-formed source. Anything else is rejected outright (`ValueError`),
    never silently downgraded to a weaker signal: an unauthorized or stale
    detection is not evidence of anything here, the same way an
    unauthorized host is refused outright in `exploit_confirmation.py`.

    "Registered, trusted source" is a policy check against `source_id`, not
    an authentication check: see the module docstring for what that does
    and does not establish.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    detection._validate(now)
    source = registry.get(detection.source_id)
    if source is None or not source.trusted:
        raise ValueError("detection source is not a registered, trusted source")
    source.validate()
    age_seconds = (now - detection.observed_at).total_seconds()
    if age_seconds > max_age_seconds:
        raise ValueError("detection is stale: urgency requires a current signal")
    assertion = "active_detection:" + detection.technique
    evidence = Evidence(asset=detection.asset, assertion=assertion, observed_pass=True,
                        observed_at=detection.observed_at,
                        source=SOURCE_PREFIX + detection.source_id, independent=True)
    return AdmissionResult(evidence=evidence, asset=detection.asset, confidence=detection.confidence)


def to_reverification_subject_update(admitted: AdmissionResult, subject: Subject, *,
                                      now_seconds: int) -> Subject:
    """Reuse the existing re-verification scheduler, rather than building a
    second one: a current, admitted detection marks its subject changed
    (so every scheduling policy treats it as immediately due) and raises
    the subject's risk floor to at least the detection's confidence. This
    does not decide whether the underlying assertion is VERIFIED; that
    still only comes from `assessment.assess` over independent evidence,
    including whatever `admit()` above produced.

    `admitted` must be the `AdmissionResult` `admit()` returned, not a raw
    `DetectionEvent`: a detection that skipped admission is rejected
    outright here, the same fail-closed way every other unvetted input is
    rejected elsewhere in this pipeline.
    """
    if not isinstance(admitted, AdmissionResult):
        raise TypeError("a raw DetectionEvent cannot update the scheduler: it must first pass admit()")
    if subject.subject_id != admitted.asset:
        raise ValueError("subject does not match the detection's asset")
    raised_risk = max(subject.risk, admitted.confidence)
    return Subject(subject_id=subject.subject_id, last_verified_at=subject.last_verified_at,
                   risk=raised_risk, changed_at=now_seconds,
                   last_probe_cost=subject.last_probe_cost)
