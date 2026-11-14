"""Bounded, opt-in, laboratory-only autonomous execution with independent checks.

Only an immediately computed eligible recommendation can drive the two
allowlisted localhost lab mutations. Not an enterprise remediation executor.
"""
from __future__ import annotations

from . import __name__ as _ignored  # avoid importing any privileged oracle into engine

def execute_lab_recommendation(recommendation: dict, *, scope_assessment: dict,
                               control_token: str, oracle_token: str,
                               action_runner=None, oracle_reader=None,
                               gateway_reader=None) -> dict:
    """Execute safe allowlisted lab recommendation and record independent evidence.

    The oracle is accessed after execution only. A control acknowledgment is
    never treated as proof of postcondition. Reboots and other disruptive
    operations always need separate human approval and are never dispatched here.
    """
    if not control_token or not oracle_token or control_token == oracle_token:
        raise ValueError("Distinct disposable control and oracle credentials required")
    if (not isinstance(scope_assessment, dict) or
            scope_assessment.get("status") != "LAB_SCOPE_SUPPORTED" or
            scope_assessment.get("production_scope_attested") is not False):
        raise ValueError("No supported isolated lab scope")
    if recommendation.get("research_lab_only") is not True:
        raise ValueError("No lab-only case boundary")
    if recommendation.get("abstained") is not False or recommendation.get("action_executed") is not False:
        raise ValueError("No fresh policy-eligible, unexecuted model selection")
    selected = recommendation.get("selected_action")
    screening = recommendation.get("screened", {}).get(selected, {})
    if screening.get("decision") != "ELIGIBLE_AUTOMATIC":
        raise ValueError("Policy gate has not authorized the selected action")
    if selected not in ("resync_policy", "gateway_restrict", "monitor_only"):
        return {"schema":"predict-shield/lab-execution-record/1",
                "status":"AWAITING_LAB_APPROVAL", "selected_action":selected,
                "action_executed":False,"independent_postcondition_verified":False}
    if action_runner is None or oracle_reader is None or gateway_reader is None:
        # Import is intentionally deferred. Engine tests never gain access to
        # the laboratory's privileged oracle or action transport.
        from pilot import perform_action, oracle_snapshot, gateway_probes
        action_runner = action_runner or perform_action
        oracle_reader = oracle_reader or oracle_snapshot
        gateway_reader = gateway_reader or (lambda: gateway_probes(24))
    # No mutation for monitor-only, but still gather full independent evidence.
    if selected != "monitor_only":
        action_runner(selected, control_token)
    oracle = oracle_reader(oracle_token)
    probes = gateway_reader()
    if not isinstance(oracle, dict) or not isinstance(probes, list):
        raise ValueError("Missing independent post-action measurements")
    complete = (oracle.get("inventory_complete") is True
                and oracle.get("direct_target_observations_complete") is True)
    truth = oracle.get("all_revoked_access_denied")
    if not complete or type(truth) is not bool:
        verdict="INDETERMINATE"
    elif truth:
        verdict="VERIFIED_LAB_ONLY"
    else:
        verdict="NOT_VERIFIED_LAB_ONLY"
    gateway_counts = {"allowed":0, "denied":0, "unknown":0}
    for probe in probes:
        code=probe.get("http_status") if isinstance(probe, dict) else None
        if code==200:
            gateway_counts["allowed"]+=1
        elif code==403:
            gateway_counts["denied"]+=1
        else:
            gateway_counts["unknown"]+=1
    return {
        "schema":"predict-shield/lab-execution-record/1",
        "selected_action":selected,
        "status":"MEASURED_LAB_ACTION" if selected!="monitor_only" else "OBSERVED_NO_ACTION",
        "action_executed":selected!="monitor_only",
        "independent_postcondition_verified":verdict=="VERIFIED_LAB_ONLY",
        "oracle_verdict":verdict,
        "independent_oracle_inventory_complete":complete,
        "gateway_probe_counts":gateway_counts,
        "gateway_probe_total":len(probes),
        "source_type":"separate_laboratory_oracle_and_gateway",
        "external_critical_infrastructure_validated":False,
        "service_continuity_verified":False,
        "lab_only":True,
    }
