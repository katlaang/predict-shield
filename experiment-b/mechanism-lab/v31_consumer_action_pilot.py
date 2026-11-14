"""Small physical v3.1 consumer-pause action pilot, NOT the registered study.

Four actual action replays; no fabricated oracle labels. This smoke can show
mechanism action differentiation but cannot pass the configuration-level gate.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from decision_eval import observed_utility
from pilot import ACTIONS, request, run_case, wait_ready

TARGET = "enforcer-b"


def resume_consumer(token: str) -> None:
    """Fail closed if actual listener cannot be resumed after a replay."""
    status, _, _ = request(TARGET, "/admin/consumer/resume",
                           method="POST", token=token)
    if status != 200:
        raise RuntimeError("Failed to restore Kafka listener after v3.1 action")
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        result, state, _ = request(TARGET, "/admin/consumer/status", token=token)
        if result == 200 and state.get("container_paused") is False:
            return
        time.sleep(0.25)
    raise RuntimeError("Kafka listener did not physically resume")


def execute(token: str, oracle_token: str) -> dict:
    if (len(token) < 24 or len(oracle_token) < 24 or
            token == oracle_token):
        raise ValueError("Two distinct disposable credentials required")
    wait_ready()
    summaries = []
    for action in ACTIONS:
        # Recover from an earlier successful pause before resetting the
        # broker revision. Also restore on failure or interrupted replay.
        resume_consumer(token)
        try:
            measured = run_case(
                action, token, oracle_token,
                ttl_ms=30000, rps=25, delay_ms=0,
                duration_seconds=5, fault_mode="consumer_paused",
                fault_target=TARGET, complexity_stratum="PARTIAL_VISIBILITY",
                gateway_includes_hidden=True,
                routing_profile="balanced")
            if measured["fault_mode"] != "consumer_paused":
                raise RuntimeError("Incorrect physical fault recorded")
            if measured["before"]["oracle"]["all_revoked_access_denied"] is not False:
                raise RuntimeError("Consumer pause did not cause initial stale authorization")
            timeline = measured["operations"]["gateway_exposure_timeline"]
            if timeline.get("valid_probe_count", 0) < 2:
                raise RuntimeError("No measured time-integrated gateway exposure")
            after = measured["after"]["oracle"]
            if not isinstance(after.get("all_revoked_access_denied"), bool):
                raise RuntimeError("Independent oracle outcome unavailable")
            ops = measured["operations"]
            costs = {
                "label_path_exposure": timeline["exposure_fraction_upper_bound"],
                "label_security_exposure": float(
                    not after["all_revoked_access_denied"]),
                "label_absolute_failed_requests": ops["non_200_requests"],
                "absolute_error_budget_requests": 25,
            }
            summaries.append({
                "action": action,
                "measured_cost": observed_utility(costs),
                "verification_status": measured["after"]["verifier_scope"]["status"],
                "oracle_all_revoked_access_denied": after["all_revoked_access_denied"],
                "observed_requests": ops["attempts"],
                "failed_requests": ops["non_200_requests"],
                "exposure_upper_fraction": timeline["exposure_fraction_upper_bound"],
                "physical_consumer_paused_pre_action": True,
            })
        finally:
            resume_consumer(token)
    if len(summaries) != len(ACTIONS) or {r["action"] for r in summaries} != set(ACTIONS):
        raise RuntimeError("Missing independently measured action arm")
    by_action = {r["action"]: r for r in summaries}
    if by_action["resync_policy"]["oracle_all_revoked_access_denied"] is True:
        raise RuntimeError("Resync wrongly appears to repair physically paused consumer")
    return {
        "schema": "predict-shield/v31-consumer-pause-smoke/1",
        "type": "independent_physical_action_replays",
        "fault": "consumer_paused",
        "replays": len(summaries),
        "decision_groups": 1,
        "measurements": summaries,
        "not_a_feasibility_gate": True,
        "not_ai_efficacy": True,
        "not_1200_trial_campaign": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute-lab", action="store_true")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not args.execute_lab:
        parser.error("Physical lab mutations require --execute-lab")
    report = execute(os.environ.get("LAB_CONTROL_TOKEN", ""),
                     os.environ.get("LAB_ORACLE_TOKEN", ""))
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"status":"MEASURED_PHYSICAL_SMOKE",
                      "arms":report["replays"],
                      "feasibility_passed":False}))


if __name__ == "__main__":
    main()
