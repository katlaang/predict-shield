"""Explicit research-only model exploration when operational policy abstains.

This code never upgrades an uncertain prediction into a production-eligible
one. It runs only in a named disposable localhost Kafka/JVM testbed and retains
the original policy-gate refusal as research evidence.
"""
from __future__ import annotations
from math import isfinite


ALLOWED = ("resync_policy", "gateway_restrict", "monitor_only")


def choose_lab_exploration(predictions, snapshot, strict_recommendation: dict,
                           *, experimental_budget: float, protocol: str) -> dict:
    if protocol != "physical-ai-exploration-v1":
        raise ValueError("Unregistered research protocol")
    if not (snapshot.trusted and snapshot.scope_complete):
        raise ValueError("Cannot explore with incomplete or untrusted lab inventory")
    if not isfinite(experimental_budget) or not 0 < experimental_budget <= 100:
        raise ValueError("Experimental budget must be positive and at most 100 requests")
    if strict_recommendation.get("abstained") is not True:
        raise ValueError("Exploration is only a recorded fallback after strict gate abstention")
    if strict_recommendation.get("research_lab_only") is not True:
        raise ValueError("No isolated research scope")
    if not predictions or len({p.action_id for p in predictions}) != len(predictions):
        raise ValueError("Missing or duplicate model predictions")
    candidates=[]
    for p in predictions:
        if p.action_id not in ALLOWED:
            continue
        if (p.snapshot_id != snapshot.snapshot_id or p.out_of_distribution
                or not p.calibration_supported or
                p.residual_risk.estimate < 0 or p.residual_risk.estimate > 1):
            continue
        impact=p.additional_errors.get("authorization")
        if impact is None or impact.estimate < 0:
            continue
        # Estimate-based ranking is an experimental intervention, NOT a safety
        # guarantee. Log uncertainty and retain the original gate result.
        score=p.residual_risk.estimate+0.5*min(1,impact.estimate/experimental_budget)
        candidates.append((score,p.action_id,p))
    if not candidates:
        return {"schema":"predict-shield/isolated-ai-exploration/1",
                "protocol":protocol,"selected_action":None,"abstained":True,
                "reason":"No in-distribution calibrated candidate available",
                "strict_policy_abstained":True,"production_authorization":False}
    score,action,p=min(candidates,key=lambda row:(row[0],row[1]))
    return {
        "schema":"predict-shield/isolated-ai-exploration/1",
        "protocol":protocol,
        "selected_action":action,
        "abstained":False,
        "model_name":p.model_name,
        "model_fingerprint":p.training_fingerprint,
        "predicted_residual_exposure":{"lower":p.residual_risk.lower,
                                       "estimate":p.residual_risk.estimate,
                                       "upper":p.residual_risk.upper},
        "predicted_additional_failed_requests":{"lower":p.additional_errors["authorization"].lower,
                                                 "estimate":p.additional_errors["authorization"].estimate,
                                                 "upper":p.additional_errors["authorization"].upper},
        "experimental_score":score,
        "strict_policy_abstained":True,
        "strict_policy_reasons":strict_recommendation["screened"],
        "high_uncertainty_accepted_for_disposable_lab_measurement_only":True,
        "production_authorization":False,
        "research_lab_only":True,
        "action_executed":False,
    }


def run_isolated_exploration(choice, *, scope, control_token, oracle_token,
                             action_runner=None, oracle_reader=None,
                             gateway_reader=None):
    if (scope.get("status")!="LAB_SCOPE_SUPPORTED"
            or scope.get("production_scope_attested") is not False):
        raise ValueError("Lab scope not supported")
    if (choice.get("schema")!="predict-shield/isolated-ai-exploration/1"
            or choice.get("protocol")!="physical-ai-exploration-v1"
            or choice.get("production_authorization") is not False
            or choice.get("strict_policy_abstained") is not True
            or choice.get("abstained") is not False
            or choice.get("action_executed") is not False):
        raise ValueError("Unregistered or reused experimental decision")
    if not control_token or not oracle_token or control_token == oracle_token:
        raise ValueError("Distinct lab tokens are required")
    action=choice.get("selected_action")
    if action not in ALLOWED:
        raise ValueError("Action not permitted in isolated exploration")
    if action_runner is None or oracle_reader is None or gateway_reader is None:
        from pilot import perform_action, oracle_snapshot, gateway_probes
        action_runner=action_runner or perform_action
        oracle_reader=oracle_reader or oracle_snapshot
        gateway_reader=gateway_reader or (lambda:gateway_probes(24))
    if action!="monitor_only":
        action_runner(action,control_token)
    oracle=oracle_reader(oracle_token)
    observations=gateway_reader()
    if not isinstance(oracle,dict) or not isinstance(observations,list):
        raise ValueError("Post-action evidence unavailable")
    valid=(oracle.get("inventory_complete") is True
           and oracle.get("direct_target_observations_complete") is True
           and type(oracle.get("all_revoked_access_denied")) is bool)
    truth=oracle.get("all_revoked_access_denied")
    verdict=("VERIFIED_LAB_ONLY" if truth else "NOT_VERIFIED_LAB_ONLY") if valid else "INDETERMINATE"
    status_counts={"allowed":0,"denied":0,"unknown":0}
    for item in observations:
        code=item.get("http_status") if isinstance(item,dict) else None
        label="allowed" if code==200 else "denied" if code==403 else "unknown"
        status_counts[label]+=1
    return {
        "schema":"predict-shield/isolated-exploratory-action-outcome/1",
        "protocol":choice["protocol"],
        "selected_action":action,
        "action_executed":action!="monitor_only",
        "oracle_verdict":verdict,
        "gateway_probe_counts":status_counts,
        "gateway_probe_total":len(observations),
        "independent_postcondition_verified":verdict=="VERIFIED_LAB_ONLY",
        "production_authorization":False,
        "scientific_superiority_established":False,
        "experimental_measurement_only":True,
    }
