"""Experiment A: incomplete remediation on a real four-JVM authorization lab.

Opt-in only. Demonstrates that correcting a gateway-visible JVM while a
separate in-scope hidden JVM remains stale must not be declared VERIFIED.
This is not a trained model, production scope inventory or AI efficacy test.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parents[1] / "experiment-b" / "mechanism-lab"
sys.path.insert(0, str(LAB))
from pilot import (gateway_probes, gateway_scope_evidence, oracle_snapshot,
                   perform_action, setup_fault, wait_for_target, wait_ready)


def run_partial(control_token: str, oracle_token: str) -> dict:
    if not control_token or not oracle_token or len(control_token) < 24 or len(oracle_token) < 24:
        raise ValueError("Disposable lab tokens required")
    if control_token == oracle_token:
        raise ValueError("Control and oracle credentials must be distinct")
    wait_ready()
    setup_fault(control_token, ttl_ms=30000, delay_ms=0,
                fault_target="enforcer-hidden", fault_mode="loss",
                oracle_token=oracle_token, gateway_includes_hidden=False)
    pre = oracle_snapshot(oracle_token)
    if pre.get("all_revoked_access_denied") is not False:
        raise RuntimeError("No actual incomplete security state before action")
    first = gateway_probes(count=6)
    if not all(x.get("http_status") == 403 for x in first):
        raise RuntimeError("Gateway does not show expected partial-view denial")
    # Correct an unrelated healthy node. The omitted hidden node retains a
    # real dropped policy event; the target is intentionally wrong.
    perform_action("restart_enforcer", control_token, fault_target="enforcer-a")
    wait_for_target("enforcer-a")
    after = oracle_snapshot(oracle_token)
    probes = gateway_probes(count=6)
    scope = gateway_scope_evidence(control_token, probes)
    if after.get("all_revoked_access_denied") is not False:
        raise RuntimeError("Residual fault healed during test; inconclusive, not a success")
    if scope.get("status") == "VERIFIED":
        raise RuntimeError("False VERIFIED despite unresolved in-scope target")
    if not all(x.get("http_status") == 403 for x in probes):
        raise RuntimeError("Expected gateway-only clean view did not persist")
    return {
        "schema": "predict-shield/experiment-a-partial-remediation/1",
        "physical_jvm_remediation_executed": True,
        "remediation_target": "enforcer-a",
        "unresolved_known_target": "enforcer-hidden",
        "gateway_visible_denials": len(probes),
        "gateway_only_appears_clean": True,
        "independent_oracle_full_scope_remediated": False,
        "independent_scope_verification": scope.get("status"),
        "outcome": "INCOMPLETE_REMEDIATION_DETECTED",
        "trained_ai_model": False,
        "external_critical_infrastructure_validation": False,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--execute-lab", action="store_true")
    p.add_argument("--output", required=True)
    a = p.parse_args()
    if not a.execute_lab:
        p.error("Physical mutation requires --execute-lab")
    result = run_partial(os.getenv("LAB_CONTROL_TOKEN", ""),
                         os.getenv("LAB_ORACLE_TOKEN", ""))
    out = Path(a.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
