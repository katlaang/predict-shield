"""Independent real Kafka committed-backlog probe in isolated Docker laboratory.

Pause a real listener; publish bounded lab policy events; observe broker
committed offset backlog through a different credential and process; resume
and verify backlog catch-up. This is NOT a cyber-defense outcome test.
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from broker_observer_v1 import BROKER_ENDPOINT, read_broker_offsets, verify_broker_evidence
from consumer_pause_smoke import wait_state
from pilot import request, wait_ready


def _accepted_publish(token: str):
    status, _, _ = request("authority", "/control/resync",
                           method="POST", token=token, timeout=10)
    if status != 202:
        raise RuntimeError("Isolated lab policy event was not queued")


def _wait_for(observer_token: str, predicate, *, timeout=35.):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        raw = read_broker_offsets(observer_token)
        last = verify_broker_evidence(raw)
        if last["status"] == "MEASURED" and predicate(last["backlog"]):
            return last
        time.sleep(.5)
    raise RuntimeError("Broker offset evidence not ready: " +
                       json.dumps(last, sort_keys=True))


def run(control_token: str, observer_token: str):
    if any(len(token) < 24 for token in (control_token, observer_token)):
        raise ValueError("Separate strong disposable lab credentials required")
    if control_token == observer_token:
        raise ValueError("Observer may not share laboratory mutation credential")
    wait_ready()
    # Authorization boundary: the separate control token cannot read the
    # observer's read-only Kafka offset endpoint.
    req = urllib.request.Request(
        BROKER_ENDPOINT, headers={"X-Lab-Observer": control_token})
    try:
        urllib.request.urlopen(req, timeout=3)
    except urllib.error.HTTPError as exc:
        if exc.code != 403:
            raise RuntimeError("Unexpected observer authorization response") from exc
    else:
        raise RuntimeError("Observer accepted the control credential")

    # Initialize the real topic and four genuine Kafka consumer-group
    # committed offsets. No artificial offset labels are written.
    for _ in range(2):
        _accepted_publish(control_token)
    before = _wait_for(observer_token, lambda backlog: all(x == 0 for x in backlog.values()))
    paused = False
    try:
        status, _, _ = request("enforcer-b", "/admin/consumer/pause",
                               method="POST", token=control_token)
        if status != 200:
            raise RuntimeError("Real Kafka pause request failed")
        paused = True
        state = wait_state(control_token, True)
        if not state.get("container_paused"):
            raise RuntimeError("Listener pause not physically observed")
        for _ in range(3):
            _accepted_publish(control_token)
        during = _wait_for(
            observer_token,
            lambda backlog: backlog["enforcer-b"] >= 1
                            and all(value == 0 for name, value in backlog.items()
                                    if name != "enforcer-b"))
    finally:
        if paused:
            status, _, _ = request("enforcer-b", "/admin/consumer/resume",
                                   method="POST", token=control_token)
            if status != 200:
                raise RuntimeError("Consumer resume failed")
            wait_state(control_token, False)
    after = _wait_for(observer_token, lambda backlog: all(x == 0 for x in backlog.values()))
    return {
        "schema": "predict-shield/physical-broker-offset-observation/1",
        "broker_observer_distinct_credential_test": "CONTROL_TOKEN_REJECTED",
        "broker_source": "independent_kafka_admin_client",
        "before": before["backlog"],
        "during_physical_pause": during["backlog"],
        "after_resuming_consumer": after["backlog"],
        "pause_witness": "KAFKA_LISTENER_ACTUALLY_PAUSED",
        "not_atomic_group_snapshot": True,
        "broker_committed_backlog_is_not_verified_processing": True,
        "security_action_executed": False,
        "outcome_oracle_read": False,
        "ai_accuracy_or_superiority_proven": False,
        "critical_infrastructure_field_validated": False,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--execute-isolated-lab", action="store_true")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if not args.execute_isolated_lab:
        p.error("Physical Kafka experiment requires explicit disposable lab flag")
    if args.output.exists():
        p.error("Refuse overwrite of prior evidence")
    report = run(os.environ.get("LAB_CONTROL_TOKEN", ""),
                 os.environ.get("LAB_OBSERVER_TOKEN", ""))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")
    print("PASS: live Kafka offset witness", report)


if __name__ == "__main__":
    main()
