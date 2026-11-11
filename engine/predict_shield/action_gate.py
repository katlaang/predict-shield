"""Fail-closed candidate screening, separate from any learned estimator.

No execution API is exposed here. The gate merely classifies a proposed
candidate as eligible for automatic use, approval, rejection or evidence escalation.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from math import isfinite

from .ai_contracts import ActionPrediction, ActionTier, CandidateAction, EvidenceSnapshot


class GateDecision(str, Enum):
    ELIGIBLE_AUTOMATIC = "ELIGIBLE_AUTOMATIC"
    PROPOSE_FOR_APPROVAL = "PROPOSE_FOR_APPROVAL"
    REJECT = "REJECT"
    ESCALATE_FOR_EVIDENCE = "ESCALATE_FOR_EVIDENCE"


@dataclass(frozen=True)
class GateResult:
    decision: GateDecision
    reason: str


def screen_action(
    snapshot: EvidenceSnapshot,
    candidate: CandidateAction,
    prediction: ActionPrediction | None,
    remaining_error_budgets: dict[str, float],
    *,
    model_max_interval_width: float = 0.50,
) -> GateResult:
    """Classify a candidate; NEVER dispatch an action.

    Budgets and predicted error increases use the same window and units.
    A human approval does not override missing evidence; insufficient evidence
    must be resolved first, even when the action is approval-tier.
    """
    if candidate.tier is ActionTier.PROHIBITED:
        return GateResult(GateDecision.REJECT, "Action prohibited by policy")
    if not snapshot.trusted or not snapshot.scope_complete:
        return GateResult(GateDecision.ESCALATE_FOR_EVIDENCE, "Untrusted or incomplete evidence scope")
    if prediction is None or prediction.action_id != candidate.action_id:
        return GateResult(GateDecision.ESCALATE_FOR_EVIDENCE, "Missing or mismatched action prediction")
    if prediction.snapshot_id != snapshot.snapshot_id or prediction.predicted_at < snapshot.captured_at:
        return GateResult(GateDecision.ESCALATE_FOR_EVIDENCE, "Prediction is not bound to the evidence snapshot")
    if prediction.out_of_distribution or not prediction.calibration_supported:
        return GateResult(GateDecision.ESCALATE_FOR_EVIDENCE, "Unsupported model calibration or out-of-distribution case")
    if prediction.residual_risk.upper - prediction.residual_risk.lower > model_max_interval_width:
        return GateResult(GateDecision.ESCALATE_FOR_EVIDENCE, "Unacceptable residual-risk uncertainty")

    for service_id in candidate.affected_services:
        budget = remaining_error_budgets.get(service_id)
        estimate = prediction.additional_errors.get(service_id)
        if budget is None or not isfinite(budget) or budget <= 0 or estimate is None:
            return GateResult(GateDecision.ESCALATE_FOR_EVIDENCE, "Missing or exhausted service error budget or impact estimate")
        if estimate.upper - estimate.lower > budget * model_max_interval_width:
            return GateResult(GateDecision.ESCALATE_FOR_EVIDENCE, "Unacceptable disruption uncertainty")
        if estimate.upper > budget:
            # Known high-impact proposal: only a policy-authorized approval tier can
            # be considered. An AUTOMATIC action can never pass the hard limit.
            if candidate.tier is ActionTier.APPROVAL:
                return GateResult(GateDecision.PROPOSE_FOR_APPROVAL, "Predicted disruption exceeds automatic safety limit")
            return GateResult(GateDecision.REJECT, "Predicted upper-bound disruption exceeds service error budget")

    if candidate.tier is ActionTier.APPROVAL:
        return GateResult(GateDecision.PROPOSE_FOR_APPROVAL, "Policy requires named human approval")
    return GateResult(GateDecision.ELIGIBLE_AUTOMATIC, "Supported evidence and conservative service gates passed")
