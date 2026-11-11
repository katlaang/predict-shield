"""Conservative, scope-aware evidence assessment.

Pre-alpha research implementation. No external systems are modified.
A trusted, current, complete independent check is required for VERIFIED.
"""
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional

class Outcome(str, Enum):
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT VERIFIED"
    INDETERMINATE = "INDETERMINATE"
    NOT_APPLICABLE = "NOT APPLICABLE"

@dataclass(frozen=True)
class Evidence:
    asset: str
    assertion: str
    observed_pass: Optional[bool]
    observed_at: datetime
    source: str
    independent: bool
    integrity_ok: bool = True

@dataclass(frozen=True)
class Assessment:
    outcome: Outcome
    conflicting_evidence: bool
    reason: str
    evidence_sources: tuple[str, ...]

def assess(
    asset: str, assertion: str, evidence: list[Evidence],
    required_independent_checks: int = 1, max_age_seconds: int = 3600,
    now: Optional[datetime] = None, applicable: bool = True
) -> Assessment:
    if not applicable:
        return Assessment(Outcome.NOT_APPLICABLE, False, "Documented assertion is outside configured applicability.", ())
    if not asset or not assertion or required_independent_checks < 1 or max_age_seconds < 0:
        raise ValueError("Invalid assessment scope or verification parameters")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    scoped = [e for e in evidence if e.asset == asset and e.assertion == assertion]
    valid = [
        e for e in scoped
        if e.integrity_ok and e.observed_at.tzinfo is not None
        and timedelta(0) <= now - e.observed_at <= timedelta(seconds=max_age_seconds)
        and e.observed_pass is not None
    ]
    conflicting = any(e.observed_pass is True for e in valid) and any(e.observed_pass is False for e in valid)
    sources = tuple(sorted({e.source for e in valid}))
    independent = {e.source for e in valid if e.independent}
    failed_independent = any(e.independent and e.observed_pass is False for e in valid)
    # INV-02: a trusted independent failure defeats a supporting self-report.
    # Record the disagreement instead of hiding it or returning INDETERMINATE.
    if failed_independent:
        return Assessment(Outcome.NOT_VERIFIED, conflicting, "Current independent check refutes the assertion.", sources)
    if conflicting:
        return Assessment(Outcome.INDETERMINATE, True, "Current evidence contradicts; independent resolution required.", sources)
    if len(independent) < required_independent_checks:
        return Assessment(Outcome.INDETERMINATE, False, "Insufficient current independent verification coverage.", sources)
    if not all(e.observed_pass is True for e in valid if e.independent):
        return Assessment(Outcome.INDETERMINATE, False, "Independent checks did not establish the assertion.", sources)
    return Assessment(Outcome.VERIFIED, False, "Current independent checks passed for the configured scope.", sources)
