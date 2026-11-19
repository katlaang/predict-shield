"""Fail-closed bridge between grid policy and an isolated Open vSwitch lab.

The signed production authority contract is NOT implemented here. This
adapter maps one registered simulated action to one fixed private-address
packet rule, checks the graph safety gate, and requires an explicit disposable
lab approval at execution. Proposals are NOT executable instructions.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from predict_shield.grid_cyber_physical_lab import (
    GridProposal, digest, load_registration, screen,
)

SCHEMA = "predict-shield/gated-ovs-packet-plan/1"
ALLOWED_ACTION = "block_untrusted_remote_management"
EXPECTED_REMOVE = [["untrusted-vpn", "remote-access-gateway"]]
PACKET_MATCH = "ip,nw_src=10.89.34.10,nw_dst=10.89.34.30"
FLOW_ADD = "priority=250," + PACKET_MATCH + ",actions=drop"


def make_plan(reg: dict, action_id: str, *, trustworthy_observations: bool) -> dict:
    """Generate a *proposal*, never authorization or switch instructions."""
    proposal = GridProposal(
        state="PROPOSED",
        action_id=action_id,
        severity="high",
        reason="synthetic registered lab scenario, not independent incident evidence",
        model_name="registered-test-double-NOT-REAL-AI",
    )
    result = screen(reg, proposal, trustworthy_observations=trustworthy_observations)
    return {
        "schema": SCHEMA,
        "registration_sha256": digest(reg),
        "scenario_id": reg["scenario_id"],
        "action_id": action_id,
        "preapproval_gate": result["decision"],
        "trusted_observations_declared": trustworthy_observations,
        "source": "synthetic-test-double-NOT-AI",
        "production_authorized": False,
        "lab_execution_authorized": False,
    }


def verify_plan(reg: dict, plan: dict, *, operator_approved: bool,
                trustworthy_observations: bool) -> dict:
    """Recompute independent gates, never trust a proposed action's claims."""
    if type(plan) is not dict or type(operator_approved) is not bool:
        raise PermissionError("invalid execution request")
    action_id = plan.get("action_id")
    if action_id != ALLOWED_ACTION:
        raise PermissionError("only the registered lab remote-access isolation can be emitted")
    expected = make_plan(reg, action_id, trustworthy_observations=trustworthy_observations)
    if plan != expected:
        raise PermissionError("plan tampering or inconsistent evidence")
    selected = next(
        (action for action in reg["actions"] if action["action_id"] == action_id), None
    )
    if (selected is None or selected["tier"] != "APPROVAL"
            or selected["remove_links"] != EXPECTED_REMOVE
            or not selected["reversible"]):
        raise PermissionError("registered protection mapping changed")
    proposal = GridProposal(
        "PROPOSED", action_id, "high", "lab fixture only",
        "registered-test-double-NOT-REAL-AI",
    )
    gate = screen(
        reg, proposal,
        trustworthy_observations=trustworthy_observations,
        operator_approved=operator_approved,
    )
    if gate["decision"] != "LAB_APPROVED_ONLY":
        raise PermissionError("independent grid policy denied packet mutation")
    return {
        "schema": "predict-shield/ovs-approved-lab-command/1",
        "action_id": action_id,
        "registration_sha256": digest(reg),
        "flow_add": FLOW_ADD,
        "flow_match_for_delete": PACKET_MATCH,
        "source": "test-double-NOT-AI",
        "lab_approved_only": True,
        "production_authorized": False,
        "grid_power_flow_coupled": False,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("operation", choices=("propose", "verify"))
    p.add_argument("--registration", type=Path, required=True)
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--action", default=ALLOWED_ACTION)
    p.add_argument("--trusted-lab-fixture", action="store_true")
    p.add_argument("--lab-operator-approved", action="store_true")
    args = p.parse_args()
    reg = load_registration(args.registration)
    if args.operation == "propose":
        output = make_plan(reg, args.action, trustworthy_observations=args.trusted_lab_fixture)
    else:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        output = verify_plan(
            reg, plan, operator_approved=args.lab_operator_approved,
            trustworthy_observations=args.trusted_lab_fixture,
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
