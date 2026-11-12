"""Opt-in consumer-only pause smoke against disposable real Kafka JVM."""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from pilot import request, wait_ready


def wait_state(token: str, expected: bool, *, timeout: float = 12.0) -> dict:
    deadline = time.monotonic() + timeout
    last = {}
    while time.monotonic() < deadline:
        status, state, _ = request("enforcer-b", "/admin/consumer/status",
                                   token=token, timeout=2.0)
        last = state
        if status == 200 and state.get("container_paused") is expected:
            return state
        time.sleep(0.35)
    raise RuntimeError("Kafka listener did not reach requested physical state: " + repr(last))


def run_consumer_pause(control_token: str, oracle_token: str) -> dict:
    if min(len(control_token), len(oracle_token)) < 24:
        raise ValueError("Distinct disposable lab credentials are required")
    if control_token == oracle_token:
        raise ValueError("Control and oracle credentials must be distinct")
    wait_ready()
    health, _, _ = request("enforcer-b", "/healthz")
    if health != 200:
        raise RuntimeError("Target JVM not initially healthy")
    paused = False
    try:
        response, _, _ = request("enforcer-b", "/admin/consumer/pause",
                                  method="POST", token=control_token)
        if response != 200:
            raise RuntimeError("Kafka pause not accepted")
        paused = True
        state = wait_state(control_token, True)
        status, pre, _ = request("enforcer-b", "/admin/state", oracle=oracle_token)
        if status != 200:
            raise RuntimeError("Private state unavailable after pause")
        health_during_pause, _, _ = request("enforcer-b", "/healthz")
        if health_during_pause != 200:
            raise RuntimeError("Whole JVM stopped instead of Kafka-only listener")
        # Actual broker publication while paused: confirm the listener
        # does not handle the event before explicit resume.
        published, _, _ = request("authority", "/control/resync",
                                   method="POST", token=control_token, timeout=10)
        if published != 202:
            raise RuntimeError("Authority could not publish test event")
        time.sleep(0.8)
        status, during, _ = request("enforcer-b", "/admin/state", oracle=oracle_token)
        if status != 200 or during["handled_events"] != pre["handled_events"]:
            raise RuntimeError("Kafka consumer handled event while reported paused")
        result = {"schema": "consumer-only-pause-v1",
                  "pause_physically_observed": state["container_paused"],
                  "http_healthy_during_pause": health_during_pause == 200,
                  "handled_events_before": pre["handled_events"],
                  "handled_events_while_paused": during["handled_events"],
                  "broker_publish_accepted": True}
    finally:
        if paused:
            response, _, _ = request("enforcer-b", "/admin/consumer/resume",
                                      method="POST", token=control_token)
            if response != 200:
                raise RuntimeError("Could not resume Kafka consumer")
            wait_state(control_token, False)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute-lab", action="store_true")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not args.execute_lab:
        parser.error("Physical mutation requires --execute-lab")
    result = run_consumer_pause(os.getenv("LAB_CONTROL_TOKEN", ""),
                                os.getenv("LAB_ORACLE_TOKEN", ""))
    p = Path(args.output)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
