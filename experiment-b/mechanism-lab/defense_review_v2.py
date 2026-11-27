"""Independent evidence-quality and resolution gate for LAB AI proposals (v2).

This module performs no training and executes no action. The old v1 frozen
selection and historical evidence remain unchanged. For automatic lab-only
dispatch, require fresh, complete, authenticated operator observations,
listener health, independently checked model reliability, and credible
predicted containment *in addition to* the existing typed policy gate.

No assertion here makes a probabilistic model safe for real infrastructure.
"""
from __future__ import annotations

import math
import time
from broker_observer_v1 import verify_broker_evidence

KNOWN = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")
MAX_AGE_S = 5.0
MAX_RESIDUAL_EXPOSURE_UPPER = 0.10  # Engineering guard for lab; not fitted.
EXPECTED_NODES = ("enforcer-a", "enforcer-b", "enforcer-c", "enforcer-hidden")


def _finite(x):
    return type(x) in (int, float) and math.isfinite(x)


def inspect_operator_evidence(pre_action: dict, *, now_monotonic: float | None = None) -> dict:
    """Fail closed on missing, stale, misidentified and unverifiable signals.

    Broker consumer lag/offset is explicitly UNKNOWN in this implementation.
    The real Spring consumer running/paused flags are measurements, not
    privileged injected fault identities.
    """
    reasons = []
    observations = pre_action.get("operator_observations") if isinstance(pre_action, dict) else None
    if not isinstance(observations, list) or len(observations) != len(EXPECTED_NODES):
        return {"status": "INSUFFICIENT", "reasons": ["INCOMPLETE_OPERATOR_INVENTORY"],
                "observed_nodes": 0, "paused_nodes": [], "lag_ground_truth": "UNKNOWN"}
    now = time.monotonic() if now_monotonic is None else now_monotonic
    if not _finite(now):
        raise ValueError("Invalid monotonic decision time")
    names, seen, paused = set(), set(), []
    revisions, handled = [], []
    signals = []
    for item in observations:
        if not isinstance(item, dict) or item.get("node") not in EXPECTED_NODES:
            reasons.append("INVALID_OPERATOR_NODE_ID")
            continue
        node = item["node"]
        if set(item) & {"fault_mode", "fault_target", "oracle", "oracle_truth",
                        "actual_revoked_access_denied", "post_action"}:
            reasons.append("PRIVILEGED_TELEMETRY_PRESENT")
        if node in names:
            reasons.append("DUPLICATE_OPERATOR_NODE")
        names.add(node)
        if item.get("observed") is not True:
            reasons.append("MISSING_OPERATOR_OBSERVATION")
            continue
        seen.add(node)
        instant = item.get("observed_at_monotonic")
        if not _finite(instant) or instant > now or now - instant > MAX_AGE_S:
            reasons.append("STALE_OR_UNTIMED_TELEMETRY")
        if item.get("consumer_state_observed") is not True:
            reasons.append("CONSUMER_HEALTH_NOT_OBSERVED")
        if type(item.get("consumer_running")) is not bool or type(item.get("consumer_paused")) is not bool:
            reasons.append("UNKNOWN_CONSUMER_HEALTH")
        elif not item["consumer_running"] or item["consumer_paused"]:
            paused.append(node)
        if type(item.get("consumer_pause_requested")) is not bool:
            reasons.append("UNKNOWN_CONSUMER_PAUSE_REQUEST")
        if item.get("broker_consumer_lag_measured") is not False:
            reasons.append("MISLABELED_BROKER_LAG")
        for key in ("applied_revision", "handled_events", "cache_age_ms",
                    "scheduled_callbacks_pending"):
            x = item.get(key)
            if type(x) is not int or x < 0:
                reasons.append("INVALID_OPERATOR_TELEMETRY")
        if type(item.get("refresh_failed")) is not bool:
            reasons.append("UNKNOWN_REFRESH_HEALTH")
        elif item["refresh_failed"]:
            signals.append("REFRESH_FAILURE_OBSERVED")
        if type(item.get("scheduled_callbacks_pending")) is int and item["scheduled_callbacks_pending"] > 0:
            signals.append("PENDING_CALLBACKS_OBSERVED")
        if type(item.get("applied_revision")) is int and item["applied_revision"] >= 0:
            revisions.append(item["applied_revision"])
        if type(item.get("handled_events")) is int and item["handled_events"] >= 0:
            handled.append(item["handled_events"])
    if names != set(EXPECTED_NODES):
        reasons.append("INVENTORY_IDENTITY_MISMATCH")
    if paused:
        reasons.append("CONSUMER_PAUSED_OR_NOT_RUNNING")
    if len(seen) != len(EXPECTED_NODES):
        reasons.append("OBSERVATION_COVERAGE_INCOMPLETE")
    if len(revisions) == len(EXPECTED_NODES) and max(revisions) != min(revisions):
        signals.append("REVISION_DIVERGENCE_OBSERVED")
    return {
        "status": "INSUFFICIENT" if reasons else "COMPLETE",
        "reasons": sorted(set(reasons)),
        "pre_action_signals": sorted(set(signals)),
        "observed_nodes": len(seen),
        "paused_nodes": sorted(paused),
        "observed_revision_spread": (max(revisions) - min(revisions)) if revisions else None,
        "observed_handled_event_spread": (max(handled) - min(handled)) if handled else None,
        "lag_ground_truth": "UNKNOWN",
        "broker_offsets_measured": False,
        "fault_identity_known": False,
        "real_authority_policy_truth_available": False,
    }


def check_model_reliability(evaluation: dict | None, bundle: dict) -> dict:
    """Do not trust an unverified 90% nominal interval as 90% actual coverage.

    The evaluation report must be checked separately against a trusted digest
    and the bundle's training fingerprint before being supplied to this gate.
    """
    if not isinstance(evaluation, dict):
        return {"status": "NOT_VERIFIED", "reasons": ["INDEPENDENT_MODEL_REPORT_MISSING"]}
    if evaluation.get("training_fingerprint") != bundle.get("training_fingerprint"):
        return {"status": "NOT_VERIFIED", "reasons": ["TRAINING_FINGERPRINT_MISMATCH"]}
    if evaluation.get("test_used_for_training_or_calibration") is not False:
        return {"status": "NOT_VERIFIED", "reasons": ["TEST_DATA_LEAKAGE_NOT_EXCLUDED"]}
    statuses = {}
    reasons = []
    for label in ("label_security_exposure", "label_absolute_failed_requests"):
        m = evaluation.get("metrics", {}).get(label, {})
        coverage = m.get("heldout_configuration_group_coverage")
        nominal = m.get("nominal_coverage")
        if not _finite(coverage) or not _finite(nominal) or not 0 < nominal <= 1 or not 0 <= coverage <= 1:
            reasons.append("UNCHECKED_" + label)
        else:
            statuses[label] = {"observed": coverage, "nominal": nominal}
            if coverage < nominal:
                reasons.append("COVERAGE_SHORTFALL_" + label)
    return {"status": "NOT_VERIFIED" if reasons else "LAB_RELIABILITY_SCREEN_PASSED",
            "reasons": reasons, "per_label": statuses,
            "not_production_calibration": True}


def review_recommendation(
    *, pre_action: dict, selected_action: str | None, predictions: tuple,
    eligible_actions: tuple[str, ...], bundle: dict,
    model_evaluation: dict | None = None,
    remaining_budget: float, now_monotonic: float | None = None,
) -> dict:
    """Separate a *proposal* from automatic authorization or verified repair.

    Residual-risk upper bound is a model uncertainty estimate and is never a
    post-action outcome. Even if passed, lab-only hard policy approval and a
    separate independent oracle remain mandatory.
    """
    if not _finite(remaining_budget) or remaining_budget <= 0:
        raise ValueError("Positive independently approved disruption budget required")
    if selected_action is not None and selected_action not in KNOWN:
        raise ValueError("Unknown selected action")
    if any(a not in KNOWN for a in eligible_actions) or len(set(eligible_actions)) != len(eligible_actions):
        raise ValueError("Unregistered action eligibility")
    telemetry = inspect_operator_evidence(pre_action, now_monotonic=now_monotonic)
    broker = verify_broker_evidence(
        pre_action.get("broker_observation") if isinstance(pre_action, dict) else None,
        now_monotonic=now_monotonic)
    reliability = check_model_reliability(model_evaluation, bundle)
    reasons = telemetry["reasons"][:] + reliability["reasons"][:]
    if broker["status"] != "MEASURED":
        reasons.append("INDEPENDENT_BROKER_EVIDENCE_UNAVAILABLE")
        reasons.extend(broker["reasons"])
    else:
        telemetry["observed_committed_backlog_per_group"] = dict(broker["backlog"])
        if any(value > 0 for value in broker["backlog"].values()):
            telemetry.setdefault("pre_action_signals", []).append(
                "BROKER_COMMITTED_BACKLOG_OBSERVED")
    details = {}
    if len(predictions) != len(KNOWN) or {p.action_id for p in predictions} != set(KNOWN):
        raise ValueError("Missing or duplicate action-specific model predictions")
    for prediction in predictions:
        if prediction.out_of_distribution or prediction.calibration_supported is not True:
            reasons.append("UNSUPPORTED_MODEL_DISTRIBUTION")
        r = prediction.residual_risk
        impact = prediction.additional_errors.get("authorization")
        if impact is None or any(not _finite(x) for x in (r.lower, r.estimate, r.upper,
                                                        impact.lower, impact.estimate, impact.upper)):
            raise ValueError("Nonfinite predicted intervals")
        if not 0 <= r.lower <= r.estimate <= r.upper <= 1:
            raise ValueError("Invalid residual-risk interval")
        if not 0 <= impact.lower <= impact.estimate <= impact.upper:
            raise ValueError("Invalid disruption interval")
        details[prediction.action_id] = {
            "predicted_residual_risk_upper": r.upper,
            "predicted_failed_requests_upper": impact.upper,
            "residual_exposure_screen_passed": r.upper <= MAX_RESIDUAL_EXPOSURE_UPPER,
            "disruption_budget_screen_passed": impact.upper <= remaining_budget,
            "eligible_under_existing_policy": prediction.action_id in eligible_actions,
        }
    if selected_action is None:
        reasons.append("NO_ACTION_SELECTED")
    elif selected_action == "monitor_only":
        reasons.append("MONITOR_ONLY_IS_NOT_REMEDIATION")
    else:
        chosen = details[selected_action]
        if selected_action == "restart_enforcer":
            reasons.append("RESTART_REQUIRES_HUMAN_APPROVAL")
        if not chosen["eligible_under_existing_policy"]:
            reasons.append("ACTION_NOT_AUTHORIZED")
        if not chosen["residual_exposure_screen_passed"]:
            reasons.append("SELECTED_ACTION_PREDICTED_UNRESOLVED")
        if not chosen["disruption_budget_screen_passed"]:
            reasons.append("SELECTED_ACTION_EXCEEDS_DISRUPTION_BUDGET")
        if selected_action == "resync_policy" and telemetry["paused_nodes"]:
            reasons.append("RESYNC_CANNOT_RESTART_PAUSED_CONSUMER")
    supported = [
        k for k, v in details.items()
        if k != "monitor_only" and v["eligible_under_existing_policy"]
        and v["residual_exposure_screen_passed"] and v["disruption_budget_screen_passed"]
    ]
    if not supported:
        reasons.append("NO_BOUNDED_EFFECTIVE_AUTOMATIC_OPTION")
    # This is not an independent safety authorization and cannot override
    # the primary policy gate. It can only veto or request review.
    veto = bool(reasons)
    return {
        "schema": "predict-shield/lab-defense-evidence-review/2",
        "status": "HUMAN_REVIEW_REQUIRED" if veto else "ELIGIBLE_FOR_LAB_REVIEWED_ACTION",
        "reasons": sorted(set(reasons)),
        "original_proposal": selected_action,
        "operator_evidence": telemetry,
        "broker_offset_evidence": broker,
        "model_reliability": reliability,
        "action_prediction_screen": details,
        "bounded_effective_candidates": supported,
        "requires_human_review": veto,
        "may_proceed_to_independent_lab_policy_gate": not veto,
        "automatic_production_execution_authorized": False,
        "post_action_resolution_verified": False,
        "critical_infrastructure_field_validated": False,
        "rules": {"max_operator_signal_age_seconds": MAX_AGE_S,
                  "max_model_residual_exposure_upper_bound": MAX_RESIDUAL_EXPOSURE_UPPER,
                  "disruption_budget": remaining_budget},
        "limitations": [
            "A passed review is not independently verified action success",
            "Research cutoff and calibrated intervals are not production safety certification",
            "Real broker lag and direct policy truth are not observed by this operator-only feed",
            "No new trained model or prospective AI superiority is created by this gate",
        ],
    }
