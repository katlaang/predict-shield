"""Four distinct physical actions during external policy-authority unavailability.

An exploratory *mechanism* measurement: observed HTTP behavior and uncertainty
bounds only, NOT an audited utility or a successful AI decision.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from authority_outage_witness import capture_witness, observe_offline
from outage_timed_measure import observe_during_action
from physical_faults import compose_command, wait_authority_unavailable
from pilot import ENFORCERS, request, setup_fault, wait_for_target, wait_ready
from python.offline_authority_witness import freeze_witness, offline_bounds

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


def collect_dual_principal_probes(request_fn, *, witness: dict,
                                  authority_http: int | None,
                                  observed_at: str) -> dict:
    """Take fresh direct HTTP measurements from all four enforcement processes.

    The revoked and legitimate test principals are synthetic identities in the
    disposable lab. The caller must separately confirm the authority outage.
    This does not supply private policy truth to an AI selector.
    """
    observations = []
    for node in ENFORCERS:
        revoked_http, _, _ = request_fn(node, "/protected", timeout=2)
        authorized_http, _, _ = request_fn(
            node, "/protected", timeout=2, authorized_lab_user=True
        )
        observations.append({
            "node": node,
            "revoked_probe_http": revoked_http,
            "legitimate_probe_http": authorized_http,
        })
    return offline_bounds(
        witness, authority_http=authority_http,
        observed_at=observed_at, nodes=observations,
    )



def verify_authority_restored(request_fn, *, oracle_token: str,
                              expected_policy: dict,
                              expected_inventory: tuple[str, ...] = ENFORCERS) -> dict:
    """Fail closed if recovering the authority silently changes the frozen trial.

    This verifies source revision continuity and target *observation scope*,
    not enforcement correctness. A recovered authority does not retroactively
    certify the outage or a previously collected HTTP observation.
    """
    status, snapshot, _ = request_fn(
        "oracle", "/oracle/observe", oracle=oracle_token, timeout=5)
    if status != 200 or not isinstance(snapshot, dict):
        raise RuntimeError("Recovery oracle unavailable; no next trial permitted")
    if snapshot.get("authority_http") != 200:
        raise RuntimeError("Authority still unavailable after restoration")
    actual = snapshot.get("authority")
    if not isinstance(expected_policy, dict) or not isinstance(actual, dict):
        raise RuntimeError("Recovery policy snapshot invalid")
    for key in ("trialId", "revision", "revoked"):
        if key not in expected_policy or actual.get(key) != expected_policy[key]:
            raise RuntimeError("Recovered authority source revision changed")
    if type(actual["revoked"]) is not bool:
        raise RuntimeError("Recovered authority revocation type invalid")
    targets = snapshot.get("targets")
    if not isinstance(targets, list) or len(targets) != len(expected_inventory):
        raise RuntimeError("Incomplete recovery observation inventory")
    identities = [urlsplit(t.get("node", "")).hostname
                  for t in targets if isinstance(t, dict)]
    if len(identities) != len(expected_inventory) or (
            set(identities) != set(expected_inventory)):
        raise RuntimeError("Recovery inventory differs from frozen experiment scope")
    return {
        "authority_source_revision_continuity_observed": True,
        "declared_target_inventory_observed": len(expected_inventory),
        "enforcement_outcome_during_outage": "INDETERMINATE",
        "next_trial_requires_fresh_setup_fault_and_quiescence": True,
    }


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
        # Capture distinct immutable-structure witness *while authority is up*.
        # Hashes alone do not attest independent custody or policy correctness.
        dual_witness = freeze_witness(
            snapshot["authority"], authority_http=snapshot["authority_http"],
            inventory=list(ENFORCERS), captured_at=witness.observed_at,
        )
        target_rows = [t for t in snapshot["targets"]
                       if urlsplit(t["node"]).hostname == TARGET]
        if len(target_rows) != 1 or target_rows[0]["direct_probe_http"] != 200:
            raise RuntimeError("Physical missed-revocation state not observed")
        stopped = False
        try:
            compose_command(["pause", "authority"], cwd=compose_dir)
            stopped = True
            wait_authority_unavailable()
            timed = observe_during_action(
                action, control, compose_dir, apply_action)
            action_result = timed["action_observation"]
            code, post, _ = request("oracle", "/oracle/observe",
                                    oracle=oracle, timeout=5)
            if code != 200:
                raise RuntimeError("Independent observer unavailable during outage")
            bounds = observe_offline(post, witness)
            # Directly probe both synthetic principal types on all four actual
            # JVMs while authority is physically stopped.
            dual_probe = collect_dual_principal_probes(
                request, witness=dual_witness,
                authority_http=post["authority_http"],
                observed_at=datetime.now(timezone.utc).isoformat(),
            )
            if dual_probe["verification_outcome"] != "INDETERMINATE":
                raise RuntimeError("Offline dual-principal data fabricated policy truth")
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
                "timed_observations": timed,
                "action_observation": action_result,
                "direct_dual_principal_observations": dual_probe,
            })
        finally:
            if stopped:
                compose_command(["unpause", "authority"], cwd=compose_dir)
                wait_ready()
                # The next action must not start if the recovered authority
                # no longer matches the policy captured before this outage.
                verify_authority_restored(
                    request, oracle_token=oracle,
                    expected_policy=dual_witness["policy"])
    if len(results) != 4:
        raise RuntimeError("Incomplete exploratory action set")
    return {"schema": "predict-shield/v31-outage-action-observations/1",
            "registered_actions": list(ACTIONS),
            "physical_action_replays": 4,
            "experiment_type": "exploratory_mechanism_only",
            "time_integrated_gateway_probes_measured": True,
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
