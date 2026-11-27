"""Untrained, isolated physical control-plane publication-loss development pilot.

Counterfactual arms: monitor-only and resync, independently reset each time.
The fault is set with mutation credentials, but its identity is NOT passed as
a model feature. Before choosing an arm, observations come solely from
authenticated operator revision, enforcer telemetry, broker group offsets and
external gateway probes. Private independent oracle accessed AFTER action.
This is exploratory mechanism evidence, not a prospectively frozen AI study.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from authority_revision_observer import collect_desired_revision, authority_revision_gap
from broker_observer_v1 import read_broker_offsets, verify_broker_evidence
from operator_telemetry_v2 import operator_telemetry_v2
from pilot import ENFORCERS, gateway_probes, oracle_snapshot, request, wait_ready

ACTIONS = ("monitor_only", "resync_policy")


def _accepted(node, path, token):
    status, result, _ = request(node, path, method="POST",
                                 token=token, timeout=10)
    if status not in (200, 202):
        raise RuntimeError("Lab mutation not accepted: " + node + path)
    return result


def _wait_condition(predicate, *, timeout=30, description="operator state"):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last is not None:
            return last
        time.sleep(.35)
    raise RuntimeError("Unable to establish measured " + description +
                       " before deadline")


def _setup_pair(control, observer):
    """Reset to allowed state and physically resync all four healthy consumers."""
    _accepted("gateway", "/admin/restore", control)
    for node in ENFORCERS:
        _accepted(node, "/admin/consumer/resume", control)
    for node in ENFORCERS:
        _wait_condition(
            lambda: True if request(node, "/admin/consumer/status",token=control)[1]
                           .get("container_paused") is False else None,
            description="Kafka resume "+node)
    reset = _accepted("authority", "/control/reset", control)
    trial_id = reset.get("trial_id")
    if not isinstance(trial_id, str) or len(trial_id) != 36:
        raise RuntimeError("Fresh authority trial identity missing")
    for node in ENFORCERS:
        _accepted(node, "/admin/reset/30000", control)
        _accepted(node, "/admin/bind/" + trial_id, control)
        _accepted(node, "/admin/fault/none/0", control)
    _accepted("authority", "/control/resync", control)

    def stable():
        revision = collect_desired_revision(observer)
        rows = operator_telemetry_v2(control)
        gaps = authority_revision_gap(revision, rows)
        broker = verify_broker_evidence(read_broker_offsets(observer))
        if gaps["status"] != "OBSERVED_OPERATOR_REVISION_GAP":
            return None
        if broker["status"] != "MEASURED":
            return None
        if any(gaps["per_node_gap"].values()) or any(broker["backlog"].values()):
            return None
        if any(row["consumer_paused"] or not row["consumer_running"]
               for row in rows):
            return None
        return True
    _wait_condition(stable, timeout=45, description="fresh allowed baseline")


def _expose_without_publish(control, observer):
    result = _accepted("authority", "/control/revoke-withheld", control)
    if result.get("publication_queued") is not False:
        raise RuntimeError("Withheld fault unexpectedly published an event")
    revision = collect_desired_revision(observer)
    rows = operator_telemetry_v2(control)
    gap = authority_revision_gap(revision, rows)
    broker = verify_broker_evidence(read_broker_offsets(observer))
    if gap["status"] != "OBSERVED_OPERATOR_REVISION_GAP":
        raise RuntimeError("No independently observable operator revision gap")
    if sorted(gap["per_node_gap"].values()) != [1, 1, 1, 1]:
        raise RuntimeError("Incorrect pre-action revision gap, test invalid")
    if broker["status"] != "MEASURED" or any(broker["backlog"].values()):
        raise RuntimeError("Broker offset evidence does not support withheld publication")
    if any(x["consumer_paused"] or not x["consumer_running"] for x in rows):
        raise RuntimeError("A consumer fault would confound publication-loss test")
    before = gateway_probes(12)
    # This is an externally observable allowed request, not private oracle.
    if not before or any(x.get("http_status") != 200 for x in before):
        raise RuntimeError("Controlled pre-action exposure not independently observed")
    return {"operator_revision_gap": gap["per_node_gap"],
            "broker_committed_backlog": broker["backlog"],
            "gateway_allowed_responses": sum(x["http_status"] == 200 for x in before),
            "pre_action_oracle_accessed": False,
            "injected_fault_label_not_supplied_as_model_input": True}


def run(control, observer, oracle_token):
    if any(not isinstance(t, str) or len(t) < 24 for t in
           (control, observer, oracle_token)) or len({control,observer,oracle_token}) != 3:
        raise ValueError("Three distinct disposal laboratory credentials needed")
    wait_ready()
    episodes = []
    for action in ACTIONS:
        _setup_pair(control, observer)
        prior = _expose_without_publish(control, observer)
        if action == "resync_policy":
            _accepted("authority", "/control/resync", control)
        # Monitor-only executes no mutation. Allow same window for both arms.
        time.sleep(2.)
        # ONLY after the action do we ask the private direct-target oracle.
        after = oracle_snapshot(oracle_token)
        if not after.get("inventory_complete") or \
                not after.get("direct_target_observations_complete"):
            raise RuntimeError("Independent oracle did not observe full target inventory")
        outcome = after.get("all_revoked_access_denied")
        if type(outcome) is not bool:
            raise RuntimeError("Cannot label absent or indeterminate physical outcome")
        episodes.append({
            "arm": action, "pre_action_observation": prior,
            "oracle_after_action": {
                "complete": True,
                "verified_revoked_access_denied_all_nodes": outcome,
            },
            "legitimate_request_disruption_measured": False,
            "action_beyond_isolated_lab": False,
        })
    return {"schema": "predict-shield/withheld-publication-dev-only/1",
            "status": "EXPLORATORY_PHYSICAL_FAULT_DEVELOPMENT",
            "source": "isolated Kafka multi-JVM with separate observer and oracle",
            "arms": episodes, "all_arms_measured": len(episodes) == 2,
            "expected_pattern_confirmed": (
                not episodes[0]["oracle_after_action"]["verified_revoked_access_denied_all_nodes"]
                and episodes[1]["oracle_after_action"]["verified_revoked_access_denied_all_nodes"]),
            "trained_model_evaluated": False,
            "preregistered_confirmatory_AI_study": False,
            "service_disruption_comparison_completed": False,
            "critical_infrastructure_effectiveness_established": False}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--execute-isolated-lab",action="store_true")
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    if not args.execute_isolated_lab:
        parser.error("Development-only physical lab requires explicit opt-in")
    if args.output.exists():
        parser.error("Refuse to overwrite historical physical result")
    report=run(os.environ.get("LAB_CONTROL_TOKEN",""),
               os.environ.get("LAB_OBSERVER_TOKEN",""),
               os.environ.get("LAB_ORACLE_TOKEN",""))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("x",encoding="utf-8") as file:
        json.dump(report,file,indent=2,sort_keys=True)
        file.write("\n")
    if not report["expected_pattern_confirmed"]:
        raise RuntimeError("Exploratory scenario failed: preserve negative result")
    print("Withheld-publication physical development evidence:", report)


if __name__=="__main__":
    main()
