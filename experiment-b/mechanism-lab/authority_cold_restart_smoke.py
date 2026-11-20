"""Opt-in disposable lab cold-restart witness, NOT an infrastructure pilot.

The authority must retain the same desired trial and revision after an actual
Docker stop/start. Any loss or mutation is a failed physical experiment.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from authority_outage_actions import verify_authority_restored
from physical_faults import compose_command, wait_authority_unavailable
from pilot import request, setup_fault, wait_ready


def execute(control: str, oracle: str, compose_dir: Path) -> dict:
    if min(len(control), len(oracle)) < 24 or control == oracle:
        raise ValueError("Distinct lab credentials required")
    wait_ready()
    setup_fault(control, ttl_ms=30000, delay_ms=0,
                fault_target="enforcer-b", fault_mode="loss",
                oracle_token=oracle, routing_profile="balanced",
                gateway_includes_hidden=True)
    before_http, before, _ = request("oracle", "/oracle/observe",
                                     oracle=oracle, timeout=5)
    if before_http != 200 or before.get("authority_http") != 200:
        raise RuntimeError("Pre-outage authority oracle unavailable")
    policy = before["authority"]
    if policy.get("revoked") is not True or not policy.get("trialId"):
        raise RuntimeError("No independently observed pre-outage revocation")
    missed = [target for target in before.get("targets", [])
              if urlsplit(target.get("node", "")).hostname == "enforcer-b"]
    if len(missed) != 1 or missed[0].get("direct_probe_http") != 200:
        raise RuntimeError("Missed event has not been physically observed")
    stopped = False
    try:
        compose_command(["stop", "authority"], cwd=compose_dir)
        stopped = True
        wait_authority_unavailable()
        outage_http, outage, _ = request("oracle", "/oracle/observe",
                                         oracle=oracle, timeout=5)
        if (outage_http != 200 or outage.get("authority_http") is not None or
                outage.get("all_revoked_access_denied") is not None):
            raise RuntimeError("Outage observer invented live policy truth")
    finally:
        if stopped:
            compose_command(["start", "authority"], cwd=compose_dir)
            wait_ready()
    recovery = verify_authority_restored(
        request, oracle_token=oracle, expected_policy=policy)
    commitment = hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "schema": "predict-shield/authority-cold-restart-witness/1",
        "environment": "isolated_docker_lab_only",
        "physical_authority_stop_and_start": True,
        "policy_snapshot_sha256": commitment,
        "authority_recovered_same_source_trial_and_revision":
            recovery["authority_source_revision_continuity_observed"],
        "full_target_scope_observed_after_recovery":
            recovery["declared_target_inventory_observed"] == 4,
        "outage_verification_outcome": "INDETERMINATE",
        "operator_field_effectiveness_established": False,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--execute-lab", action="store_true")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if not args.execute_lab:
        p.error("Cold restart requires disposable physical lab")
    result = execute(os.getenv("LAB_CONTROL_TOKEN", ""),
                     os.getenv("LAB_ORACLE_TOKEN", ""),
                     Path(__file__).resolve().parent)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as out:
        json.dump(result, out, indent=2, sort_keys=True)
        out.write("\n")


if __name__ == "__main__":
    main()
