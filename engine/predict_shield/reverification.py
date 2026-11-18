"""Deterministic re-verification scheduling policies.

Offline component. It schedules *requests* for independent probes and
never executes probes, labels an action VERIFIED, or accesses the private oracle.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import isfinite


@dataclass(frozen=True)
class Subject:
    subject_id: str
    last_verified_at: int
    risk: float
    changed_at: int | None = None
    last_probe_cost: int = 1

    def validate(self, now: int) -> None:
        if not self.subject_id:
            raise ValueError("subject_id required")
        if self.last_verified_at < 0 or self.last_verified_at > now:
            raise ValueError("invalid last_verified_at")
        if self.changed_at is not None and (self.changed_at < 0 or self.changed_at > now):
            raise ValueError("invalid changed_at")
        if not isfinite(self.risk) or not 0 <= self.risk <= 1:
            raise ValueError("risk must be finite in [0,1]")
        if not isinstance(self.last_probe_cost, int) or self.last_probe_cost < 1:
            raise ValueError("probe cost must be positive integer")


@dataclass(frozen=True)
class ProbeRequest:
    subject_id: str
    due_to: str
    units: int


def schedule(subjects: list[Subject], *, now: int, budget: int,
             policy: str, interval: int = 60,
             high_risk_after: int = 15, high_risk_cutoff: float = 0.7
             ) -> list[ProbeRequest]:
    """Select due checks within the same discrete probe-unit budget.

    'fixed': due if elapsed >= interval
    'change': due if changed since last verification
    'adaptive': due if changed, interval elapsed, or high-risk shortened window

    Fixed and change policies are deterministic schedules; 'adaptive' is an
    explicitly heuristic schedule, not a learned regression predictor.
    """
    if now < 0 or budget < 0 or interval < 1 or high_risk_after < 1:
        raise ValueError("invalid time, budget or intervals")
    if not 0 <= high_risk_cutoff <= 1:
        raise ValueError("high_risk_cutoff outside [0,1]")
    if policy not in {"fixed", "change", "adaptive"}:
        raise ValueError("unknown policy")
    if len({s.subject_id for s in subjects}) != len(subjects):
        raise ValueError("duplicate subject_id")
    queued = []
    for item in subjects:
        item.validate(now)
        age = now - item.last_verified_at
        changed = item.changed_at is not None and item.changed_at > item.last_verified_at
        fixed_due = age >= interval
        risk_due = item.risk >= high_risk_cutoff and age >= high_risk_after
        if policy == "fixed":
            due = fixed_due
            reason = "fixed_interval"
        elif policy == "change":
            due = changed
            reason = "change_event"
        else:
            due = changed or fixed_due or risk_due
            reason = ("change_event" if changed else
                      "risk_age" if risk_due else "fixed_interval")
        if due:
            # Fixed prespecified prioritization, stable tie-break by subject ID.
            priority = (int(changed), item.risk, age, item.subject_id)
            queued.append((priority, ProbeRequest(item.subject_id, reason, item.last_probe_cost)))
    # Only operator-visible features enter the ranking; no regression labels.
    queued.sort(key=lambda entry: (-entry[0][0], -entry[0][1],
                                   -entry[0][2], entry[0][3]))
    selected = []
    remaining = budget
    for _, request in queued:
        if request.units <= remaining:
            selected.append(request)
            remaining -= request.units
    return selected
