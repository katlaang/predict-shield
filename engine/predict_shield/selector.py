"""Policy-constrained defensive action selector for the Experiment B lab loop.

This component connects model predictions to the existing fail-closed action
gate and ranks *eligible* actions by estimated residual risk and normalized
service disruption. It never directly executes an action, grants approval,
or establishes verification. An inference adapter must construct these
predictions from a trained, calibrated model using pre-action observations.
Missing or unsupported predictions result in abstention.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Mapping

from .action_gate import GateDecision, GateResult, screen_action
from .ai_contracts import ActionPrediction, CandidateAction, EvidenceSnapshot


@dataclass(frozen=True)
class RankedAction:
    """One permitted action and its policy-constrained predicted utility."""
    action_id: str
    score: float
    estimated_residual_risk: float
    normalized_service_disruption: float


@dataclass(frozen=True)
class Selection:
    """Immutable selection output without a capability to dispatch an action."""
    selected: RankedAction | None
    eligible: tuple[RankedAction, ...]
    screened: Mapping[str, GateResult]
    abstained: bool
    reason: str


def select_action(
    snapshot: EvidenceSnapshot,
    candidates: tuple[CandidateAction, ...],
    predictions: tuple[ActionPrediction, ...],
    remaining_error_budgets: dict[str, float],
    *,
    disruption_weight: float = 0.5,
    service_weights: Mapping[str, float] | None = None,
) -> Selection:
    """Screen all proposals and rank only automatically permitted candidates.

    Scoring is S(a) = R(a) + lambda * D(a), where R is normalized learned
    residual security risk and D is a weighted average of predicted
    additional errors divided by positive service remaining error budgets.
    Predictions cannot bypass hard service-budget limits or authorization.
    The first candidate is never privileged merely because it occurs first.

    No counterfactual labels, test-set oracle truth, execution acknowledgments
    or post-action verifier results may be used as inputs to this method.
    """
    if not isfinite(disruption_weight) or disruption_weight < 0:
        raise ValueError("disruption weight must be finite and nonnegative")
    if len({c.action_id for c in candidates}) != len(candidates):
        raise ValueError("duplicate candidate action ID")
    if len({p.action_id for p in predictions}) != len(predictions):
        raise ValueError("duplicate prediction action ID")
    supplied = {p.action_id: p for p in predictions}
    weights = dict(service_weights or {})
    if any((not isfinite(value) or value <= 0) for value in weights.values()):
        raise ValueError("service weights must be finite positive numbers")
    screened: dict[str, GateResult] = {}
    allowed: list[RankedAction] = []
    for candidate in candidates:
        if not candidate.affected_services:
            screened[candidate.action_id] = GateResult(
                GateDecision.ESCALATE_FOR_EVIDENCE, "Missing affected-service closure"
            )
            continue
        prediction = supplied.get(candidate.action_id)
        gate = screen_action(
            snapshot, candidate, prediction, remaining_error_budgets
        )
        screened[candidate.action_id] = gate
        if gate.decision is not GateDecision.ELIGIBLE_AUTOMATIC:
            continue
        assert prediction is not None  # gate requires a matching prediction
        total_weight, total_disruption = 0.0, 0.0
        for service in candidate.affected_services:
            weight = weights.get(service, 1.0)
            total_weight += weight
            total_disruption += weight * min(
                1.0,
                prediction.additional_errors[service].estimate
                / remaining_error_budgets[service]
            )
        disruption = total_disruption / total_weight
        risk = prediction.residual_risk.estimate
        allowed.append(RankedAction(
            action_id=candidate.action_id,
            score=risk + disruption_weight * disruption,
            estimated_residual_risk=risk,
            normalized_service_disruption=disruption,
        ))
    allowed.sort(key=lambda item: (item.score, item.action_id))
    if not allowed:
        return Selection(
            selected=None, eligible=(), screened=screened,
            abstained=True,
            reason="No automatically permitted action with supported prediction and evidence",
        )
    return Selection(
        selected=allowed[0], eligible=tuple(allowed), screened=screened,
        abstained=False,
        reason="Selected minimum predicted risk-plus-disruption among policy-eligible actions",
    )
