"""Exploratory interval-valued action-cost diagnostic for authority outage.

Uses only physically observed timed gateway probes, real user HTTP failures,
and independent four-node direct-probe lower/upper bounds. Live policy truth
is UNKNOWN and the retained residual-control component remains [0, 1],
except when a real unauthorized allow makes its LOWER bound 1.

No scalar verdict, learned decision, preregistered utility, or final v3.1 gate.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")
COMPONENT_WEIGHTS = {
    "timed_gateway_exposure": 0.50,
    "residual_policy_risk": 0.25,
    "observed_user_failures": 0.25,
}
SCHEMA = "predict-shield/outage-interval-diagnostic/1"


def _number(value: object, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("Nonfinite or nonnumeric " + label)
    return float(value)


def interval_cost(action: dict, *, error_budget_requests: int) -> dict:
    if type(error_budget_requests) is not int or error_budget_requests <= 0:
        raise ValueError("Positive preregistered absolute request allowance required")
    action_id = action.get("action")
    witnessed_status = {
        "resync_policy": "TRANSPORT_UNAVAILABLE",
        "restart_enforcer": "JVM_RESTART_OBSERVED",
        "gateway_restrict": "GATEWAY_RESTRICTION_ACCEPTED",
        "monitor_only": "NO_ACTION",
    }
    observation = action.get("action_observation")
    if (action_id not in witnessed_status
            or not isinstance(observation, dict)
            or observation.get("action_status") != witnessed_status[action_id]):
        raise ValueError("Physical action acknowledgement does not match the registered action")
    if (action.get("policy_truth") != "UNKNOWN" or
            action.get("verification_status") != "INDETERMINATE"):
        raise ValueError("The authority-outage diagnostic cannot use a VERIFIED oracle")
    timed = action.get("timed_observations")
    if not isinstance(timed, dict) or timed.get("schema") != "predict-shield/outage-timed-observations/1":
        raise ValueError("Requires actual timed physical observation schema")
    if timed.get("policy_verification_from_this_measurement") != "NOT_EVALUATED":
        raise ValueError("Timed gateway observation is not authoritative verification")
    exposure = timed.get("revoked_gateway_exposure") or {}
    if exposure.get("method") != "monotonic_http_step_integral" or (
            type(exposure.get("valid_probe_count")) is not int or
            exposure["valid_probe_count"] < 2):
        raise ValueError("Insufficient physical timed gateway probes")
    low = _number(exposure.get("exposure_fraction_lower_bound"), "gateway lower")
    high = _number(exposure.get("exposure_fraction_upper_bound"), "gateway upper")
    if not 0 <= low <= high <= 1:
        raise ValueError("Invalid exposure intervals")
    duration = _number(exposure.get("window_seconds"), "measurement duration")
    seconds_low = _number(exposure.get("exposure_seconds_lower_bound"), "exposure seconds lower")
    seconds_high = _number(exposure.get("exposure_seconds_upper_bound"), "exposure seconds upper")
    if (not 0 < duration <= 30 or not 0 <= seconds_low <= seconds_high <= duration
            or abs(seconds_low / duration - low) > 1e-8
            or abs(seconds_high / duration - high) > 1e-8):
        raise ValueError("Inconsistent measured exposure seconds and fractions")
    target_count = action.get("observed_allow_count")
    deny_count = action.get("observed_deny_count")
    unknown_count = action.get("unknown_target_count")
    if any(type(v) is not int or v < 0 for v in (target_count, deny_count, unknown_count)):
        raise ValueError("Invalid four-node observation counts")
    if target_count + deny_count + unknown_count != 4:
        raise ValueError("Incomplete independent four-node inventory")
    # A known unauthorized direct allow proves unresolved historical-policy
    # exposure in this observation. A denial never proves live authority
    # correctness while its truth source remains unavailable.
    risk_low = float(target_count > 0)
    risk_high = 1.0
    user_failures = 0
    denominator = 0
    counts = {}
    for key in ("authorized_protected", "legitimate_endpoint"):
        item = timed.get(key) or {}
        total, failures = item.get("requests"), item.get("non_200_requests")
        if (type(total) is not int or total < 1 or
                type(failures) is not int or not 0 <= failures <= total):
            raise ValueError("Invalid observed user failure numerator or denominator")
        statuses = item.get("http_status_counts")
        if (not isinstance(statuses, dict) or
                any(not isinstance(k, str) or type(v) is not int or v < 0 for k, v in statuses.items()) or
                sum(statuses.values()) != total or
                total - statuses.get("200", 0) != failures):
            raise ValueError("Inconsistent measured HTTP status accounting")
        denominator += total
        user_failures += failures
        counts[key] = {"requests": total, "failed": failures}
    disruption = user_failures / error_budget_requests
    lower = (COMPONENT_WEIGHTS["timed_gateway_exposure"] * low +
             COMPONENT_WEIGHTS["residual_policy_risk"] * risk_low +
             COMPONENT_WEIGHTS["observed_user_failures"] * disruption)
    upper = (COMPONENT_WEIGHTS["timed_gateway_exposure"] * high +
             COMPONENT_WEIGHTS["residual_policy_risk"] * risk_high +
             COMPONENT_WEIGHTS["observed_user_failures"] * disruption)
    if lower > upper + 1e-12:
        raise ValueError("Interval ordering violated")
    return {
        "action": action["action"],
        "cost_lower_bound": lower,
        "cost_upper_bound": upper,
        "timed_exposure_lower_bound": low,
        "timed_exposure_upper_bound": high,
        "unresolved_policy_indicator_lower_bound": risk_low,
        "unresolved_policy_indicator_upper_bound": risk_high,
        "observed_user_failure_count": user_failures,
        "observed_user_request_count": denominator,
        "per_user_category": counts,
        "absolute_error_budget_requests": error_budget_requests,
        "uncertainty_is_not_a_statistical_confidence_interval": True,
    }


def evaluate(report: dict, *, error_budget_requests: int,
             restart_permitted: bool) -> dict:
    """Conservative partial-order comparison, no invented best action."""
    if type(restart_permitted) is not bool:
        raise ValueError("Change-policy restart eligibility must be explicit")
    if (report.get("schema") != "predict-shield/v31-outage-action-observations/1"
            or report.get("physical_action_replays") != 4
            or report.get("decision_value_computed") is not False
            or report.get("v31_feasibility_evaluated") is not False):
        raise ValueError("Only the raw four-action exploratory physical report is eligible")
    raw = report.get("results")
    if (not isinstance(raw, list) or len(raw) != 4 or
            {r.get("action") for r in raw} != set(ACTIONS)):
        raise ValueError("All four distinct physical action arms required")
    witnesses = {r.get("witness_sha256") for r in raw}
    if any(not isinstance(w, str) or len(w) != 64 or any(c not in "0123456789abcdef" for c in w)
           for w in witnesses):
        raise ValueError("Missing or invalid pre-outage commitment")
    # Each arm is an independently reset trial. Witnesses should NOT match
    # across arms, or one arm may have been inadvertently replayed twice.
    if len(witnesses) != 4:
        raise ValueError("Missing independent policy witnesses across the four arms")
    scored = {r["action"]: interval_cost(r, error_budget_requests=error_budget_requests)
              for r in raw}
    # This diagnostic is *only* for a physically stopped authority known to
    # the operator before action selection. A resync requiring that offline
    # service is NOT a viable choice. Its physical replay remains necessary
    # to document mechanism impossibility but cannot earn "model" headroom.
    feasible = [a for a in ACTIONS
                if a != "resync_policy"
                and (restart_permitted or a != "restart_enforcer")]
    dominance = {}
    for a in feasible:
        dominance[a] = [b for b in feasible
                        if b != a and
                        scored[a]["cost_upper_bound"] < scored[b]["cost_lower_bound"]]
    definitive = [a for a in feasible if len(dominance[a]) == len(feasible) - 1]
    return {
        "schema": SCHEMA,
        "source_report_schema": report["schema"],
        "weight_policy": "EXPLORATORY_REUSE_OF_V3_WEIGHTS_NOT_REGISTERED_V31_OUTAGE_OBJECTIVE",
        "weights": COMPONENT_WEIGHTS,
        "registered_error_allowance_assumed": error_budget_requests,
        "restart_permitted": restart_permitted,
        "authority_known_offline_before_action": True,
        "resync_replay_preserved_for_mechanism_only": True,
        "fixed_resync_is_ineligible": True,
        "physically_replayed_actions": list(ACTIONS),
        "feasible_actions_for_offline_comparison": feasible,
        "action_intervals": [scored[a] for a in ACTIONS],
        "strict_interval_dominance": dominance,
        "unique_definite_best_action": definitive[0] if len(definitive) == 1 else None,
        "status": "EXPLORATORY_INTERVALS_ONLY",
        "uncertainty_bands_not_sampling_confidence_intervals": True,
        "not_a_frozen_v31_primary_utility": True,
        "not_ai_training_or_inference": True,
        "not_v31_feasibility_or_campaign_authorization": True,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--physical-report", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--error-budget-requests", type=int, required=True)
    eligible = p.add_mutually_exclusive_group(required=True)
    eligible.add_argument("--restart-permitted", action="store_true")
    eligible.add_argument("--restart-prohibited", action="store_true")
    args = p.parse_args()
    result = evaluate(json.loads(args.physical_report.read_text()),
                      error_budget_requests=args.error_budget_requests,
                      restart_permitted=args.restart_permitted)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps({"status": result["status"],
                      "unique_definite_best_action": result["unique_definite_best_action"],
                      "not_v31_feasibility_or_campaign_authorization": True}))


if __name__ == "__main__":
    main()
