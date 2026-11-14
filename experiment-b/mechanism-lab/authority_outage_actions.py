"""Four distinct physical actions during external policy-authority unavailability.

An exploratory *mechanism* comparison: observed HTTP behavior and uncertainty
bounds only, NOT an audited v3.1 regret/utility or a successful AI decision.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from authority_outage_witness import capture_witness, observe_offline
from physical_faults import compose_command, wait_authority_unavailable
from pilot import request, setup_fault, wait_for_target, wait_ready

ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")
TARGET = "enforcer-b"


def apply_action(action: str, control: str, compose_dir: Path) -> dict:
    """Observe actual action transport, not an intended recovery label."""
    if action not in ACTIONS:
        raise ValueError("Unregistered corrective action")
    if action == "resync_policy":
        status, _, elapsed = request(
            "authority", "/control/resync", method="POST", token=control, timeout=1)
        # A stopped authority must not pretend publication occurred.
        if status is not None:
            raise RuntimeError("Authority became reachable during outage")
        return {"action_status": "TRANSPORT_UNAVAILABLE",
                "action_http_status": None, "action_latency_ms": elapsed}
    if action == "restart_enforcer":
        compose_command(["restart", TARGET], cwd=compose_dir)
        seconds = wait_for_target(TARGET)
        return {"action_status": "JVM_RESTART_OBSERVED",
                "action_http_status": None, "restart_recovery_seconds": seconds}
    if action == "gateway_restrict":
        status, _, elapsed = request(
            "gateway", "/admin/restrict", method="POST", token=control, timeout=3)
        if status != 200:
            raise RuntimeError("Gateway restriction failed")
        return {"action_status": "GATEWAY_RESTRICTION_ACCEPTED",
                "action_http_status": status, "action_latency_ms": elapsed}
    return {"action_status": "NO_ACTION", "action_http_status": None}


def sample_gateway(*, count: int = 8) -> dict:
    """Measure revoked/authorized traffic, retaining unknown HTTP outcomes."""
    if count < 2:
        raise ValueError("At least two real HTTP probes required")
    revoked, authorized = {}, {}
    for _ in range(count):
        for category, kwargs, counts in (
            ("revoked", {}, revoked),
            ("authorized", {"authorized_lab_user": True}, authorized),
        ):
            status, _, _ = request("gateway", "/protected", timeout=2, **kwargs)
            key = str(status) if status is not None else "unreachable"
            counts[key] = counts.get(key, 0) + 1
    return {"revoked": revoked, "authorized": authorized,
            "probe_count_each_principal": count}


def execute(control: str, oracle: str, compose_dir: Path) -> dict:
    if min(len(control), len(oracle)) < 24 or control == oracle:
        raise ValueError("Distinct disposable control and oracle credentials required")
    wait_ready()
    results = []
    for action in ACTIONS:
        # Setup occurs while authority is online. This creates a fresh,
        # independently confirmed historical policy revocation with real loss.
        setup_fault(control, ttl_ms=30000, delay_ms=0,
                    fault_target=TARGET, fault_mode="loss", oracle_token=oracle,
                    routing_profile="balanced", gateway_includes_hidden=True)
        code, snapshot, _ = request("oracle", "/oracle/observe", oracle=oracle, timeout=5)
        if code != 200:
            raise RuntimeError("Unable to collect authentic pre-outage witness")
        witness = capture_witness(snapshot, observed_at=datetime.now(timezone.utc))
        target_rows = [t for t in snapshot["targets"]
                       if urlsplit(t["node"]).hostname == TARGET]
        if len(target_rows) != 1 or target_rows[0]["direct_probe_http"] != 200:
            raise RuntimeError("Physical missed-revocation state not observed")
        stopped = False
        try:
            compose_command(["stop", "authority"], cwd=compose_dir)
            stopped = True
            wait_authority_unavailable()
            initial = sample_gateway()
            action_result = apply_action(action, control, compose_dir)
            subsequent = sample_gateway()
            code, post, _ = request("oracle", "/oracle/observe",
                                    oracle=oracle, timeout=5)
            if code != 200:
                raise RuntimeError("Independent observer unavailable during outage")
            bounds = observe_offline(post, witness)
            if bounds["verification_status"] != "INDETERMINATE":
                raise RuntimeError("Offline policy was incorrectly certified")
            results.append({
                "action": action,
                "witness_sha256": witness.commitment_sha256,
                "policy_truth": bounds["authority_truth_status"],
                "verification_status": bounds["verification_status"],
                "observed_allow_count": bounds["observed_allow_count"],
                "observed_deny_count": bounds["observed_deny_count"],
                "unknown_target_count": bounds["unknown_target_count"],
                "observed_allow_fraction_lower_bound": bounds[
                    "observed_allow_fraction_lower_bound"],
                "observed_allow_fraction_upper_bound": bounds[
                    "observed_allow_fraction_upper_bound"],
                "gateway_before": initial,
                "gateway_after": subsequent,
                "action_observation": action_result,
            })
        finally:
            if stopped:
                compose_command(["start", "authority"], cwd=compose_dir)
                wait_ready()
    if len(results) != 4:
        raise RuntimeError("Incomplete exploratory action set")
    return {"schema": "predict-shield/v31-outage-action-observations/1",
            "registered_actions": list(ACTIONS),
            "physical_action_replays": 4,
            "experiment_type": "exploratory_mechanism_only",
            "decision_value_computed": False,
            "v31_feasibility_evaluated": False,
            "private_policy_truth_not_used_as_live_verification": True,
            "results": results}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute-lab", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.execute_lab:
        parser.error("Physical mutations require --execute-lab")
    result = execute(os.getenv("LAB_CONTROL_TOKEN", ""),
                     os.getenv("LAB_ORACLE_TOKEN", ""),
                     Path(__file__).resolve().parent)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
