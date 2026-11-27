"""Read-only v2 operator telemetry witness against disposable Spring/Kafka lab.

The only mutations are the explicit bounded Kafka-listener pause/resume in the
isolated laboratory. No threat is generated, no security action is performed,
no model is trained, and no claim of correct defense is made.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from defense_review_v2 import EXPECTED_NODES, inspect_operator_evidence
from pilot import request, wait_ready
from operator_telemetry_v2 import operator_telemetry_v2


def _poll(token: str, *, paused: bool, timeout: float = 18.) -> dict:
    started = time.monotonic()
    last = {}
    while time.monotonic() - started < timeout:
        rows = operator_telemetry_v2(token)
        report = inspect_operator_evidence(
            {"operator_observations": rows}, now_monotonic=time.monotonic())
        last = report
        exact = report["paused_nodes"] == (["enforcer-b"] if paused else [])
        if exact and (report["status"] == "COMPLETE" if not paused
                      else report["reasons"] == ["CONSUMER_PAUSED_OR_NOT_RUNNING"]):
            return report
        time.sleep(.4)
    raise RuntimeError("New operator feed failed physical pause-state observation: "
                       + json.dumps(last, sort_keys=True))


def run(token: str) -> dict:
    if not isinstance(token, str) or len(token) < 24:
        raise ValueError("Laboratory control credential required")
    wait_ready()
    before = _poll(token, paused=False)
    mutated = False
    try:
        status, _, _ = request("enforcer-b", "/admin/consumer/pause",
                               method="POST", token=token)
        if status != 200:
            raise RuntimeError("Physical Kafka consumer pause not accepted")
        mutated = True
        during = _poll(token, paused=True)
    finally:
        if mutated:
            status, _, _ = request("enforcer-b", "/admin/consumer/resume",
                                   method="POST", token=token)
            if status != 200:
                raise RuntimeError("Could not restore Kafka consumer after operator test")
    restored = _poll(token, paused=False)
    return {
        "schema": "predict-shield/preaction-operator-health-physical-smoke/2",
        "observed_inventory": list(EXPECTED_NODES),
        "before": {"status": before["status"], "paused_nodes": before["paused_nodes"]},
        "physical_paused_signal": {"status": during["status"],
                                   "paused_nodes": during["paused_nodes"],
                                   "reasons": during["reasons"]},
        "restored": {"status": restored["status"], "paused_nodes": restored["paused_nodes"]},
        "real_broker_lag_observed": False,
        "injected_fault_label_read": False,
        "security_action_executed": False,
        "ai_decision_superiority_established": False,
        "critical_infrastructure_field_validated": False,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--execute-isolated-lab", action="store_true")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if not args.execute_isolated_lab:
        p.error("Only explicitly authorized disposable lab pause/resume allowed")
    if args.output.exists():
        p.error("Refuse overwriting a previous observation")
    result = run(os.environ.get("LAB_CONTROL_TOKEN", ""))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as f:
        f.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Operator health test passed:", result["physical_paused_signal"])


if __name__ == "__main__":
    main()
