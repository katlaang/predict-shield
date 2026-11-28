"""Read-only prospective paired defense evidence quality and score audit.

Input JSON is an array of measured rows. Each row represents one separately
executed physical action arm, not a simultaneous counterfactual. This module
does not train a model, choose an action, or authorize execution.

Required fields per row:
 configuration_id, repeat, action, partition, restart_permitted,
 absolute_error_budget_requests, label_security_exposure,
 label_absolute_failed_requests, pre_action_hash, oracle_verified

One separate JSON decisions array contains:
 configuration_id, repeat, policy, selected_action, evidence_hash
The same evidence_hash must be used by all policies for a matched episode.
"""
from __future__ import annotations
from collections import defaultdict
import argparse
import json
from pathlib import Path

ACTIONS = ("monitor_only", "resync_policy", "restart_enforcer", "gateway_restrict")
POLICIES = ("ai", "expert")
REQUIRED = {
    "configuration_id", "repeat", "action", "partition",
    "restart_permitted", "absolute_error_budget_requests",
    "label_security_exposure", "label_absolute_failed_requests",
    "pre_action_hash", "oracle_verified",
}
DECISION_REQUIRED = {"configuration_id", "repeat", "policy", "selected_action", "evidence_hash"}


def audit(rows: list[dict], decisions: list[dict]) -> dict:
    if not rows or not decisions:
        raise ValueError("Measured arms and independently frozen decisions required")
    arms = defaultdict(dict)
    decisions_by_episode = defaultdict(dict)
    partitions = {}
    for r in rows:
        if not isinstance(r, dict) or not REQUIRED.issubset(r):
            raise ValueError("Incomplete measured action arm")
        group, repeat, action = r["configuration_id"], r["repeat"], r["action"]
        if not isinstance(group, str) or not group or type(repeat) is not int or repeat < 0:
            raise ValueError("Invalid group or repeat identity")
        if action not in ACTIONS or r["partition"] != "test":
            raise ValueError("Unregistered action or non-test evidence")
        if type(r["restart_permitted"]) is not bool or type(r["oracle_verified"]) is not bool:
            raise ValueError("Authorization and oracle completeness must be booleans")
        if not r["oracle_verified"]:
            raise ValueError("Unverified oracle result cannot be scored")
        if type(r["absolute_error_budget_requests"]) not in (int, float) or r["absolute_error_budget_requests"] <= 0:
            raise ValueError("Invalid approved budget")
        if type(r["label_security_exposure"]) not in (int, float) or not 0 <= r["label_security_exposure"] <= 1:
            raise ValueError("Invalid exposure measurement")
        if type(r["label_absolute_failed_requests"]) is not int or r["label_absolute_failed_requests"] < 0:
            raise ValueError("Invalid observed failed request count")
        if not isinstance(r["pre_action_hash"], str) or len(r["pre_action_hash"]) != 64:
            raise ValueError("Unpinned observation")
        episode = (group, repeat)
        if action in arms[episode]:
            raise ValueError("Duplicate measured action arm")
        arms[episode][action] = r
        if group in partitions and partitions[group] != r["partition"]:
            raise ValueError("Group crossed partitions")
        partitions[group] = r["partition"]
    for d in decisions:
        if not isinstance(d, dict) or not DECISION_REQUIRED.issubset(d):
            raise ValueError("Incomplete frozen policy decision")
        episode = (d["configuration_id"], d["repeat"])
        policy, action = d["policy"], d["selected_action"]
        if policy not in POLICIES or action not in ACTIONS:
            raise ValueError("Unknown policy/action")
        if policy in decisions_by_episode[episode]:
            raise ValueError("Duplicate policy decision")
        if not isinstance(d["evidence_hash"], str) or len(d["evidence_hash"]) != 64:
            raise ValueError("Missing frozen decision observation hash")
        decisions_by_episode[episode][policy] = d
    if set(arms) != set(decisions_by_episode):
        raise ValueError("Incomplete correspondence between physical arms and decisions")
    aggregate = {policy: defaultdict(list) for policy in POLICIES}
    for episode, action_rows in arms.items():
        if set(action_rows) != set(ACTIONS):
            raise ValueError("Every paired episode requires all four physically measured actions")
        expected = action_rows["monitor_only"]
        if any((r["restart_permitted"], r["absolute_error_budget_requests"], r["pre_action_hash"])
               != (expected["restart_permitted"], expected["absolute_error_budget_requests"], expected["pre_action_hash"])
               for r in action_rows.values()):
            raise ValueError("Mismatched authorization, budget or pre-action evidence")
        frozen = decisions_by_episode[episode]
        if set(frozen) != set(POLICIES):
            raise ValueError("AI and expert decisions both required")
        if any(d["evidence_hash"] != expected["pre_action_hash"] for d in frozen.values()):
            raise ValueError("Decision input differs from frozen measured pre-action evidence")
        for policy, decision in frozen.items():
            action = decision["selected_action"]
            if action == "restart_enforcer" and not expected["restart_permitted"]:
                raise ValueError("Prohibited restart recommended; do not silently replace with monitor")
            r = action_rows[action]
            aggregate[policy][episode[0]].append({
                "resolved": r["label_security_exposure"] == 0,
                "failed_requests": r["label_absolute_failed_requests"],
                "budget_breach": r["label_absolute_failed_requests"] > r["absolute_error_budget_requests"],
                "cost": (0.75 * r["label_security_exposure"]
                         + 0.25 * r["label_absolute_failed_requests"] / r["absolute_error_budget_requests"]),
            })
    summaries = {}
    for policy, groups in aggregate.items():
        group_means = [sum(x["cost"] for x in records)/len(records) for records in groups.values()]
        samples = [r for records in groups.values() for r in records]
        summaries[policy] = {
            "configuration_groups": len(groups),
            "episodes": len(samples),
            "mean_group_cost": sum(group_means)/len(group_means),
            "resolved_episodes": sum(x["resolved"] for x in samples),
            "failed_legitimate_requests": sum(x["failed_requests"] for x in samples),
            "observed_budget_breaches": sum(x["budget_breach"] for x in samples),
            "per_group_mean_cost": dict(zip(sorted(groups), [
                sum(x["cost"] for x in groups[g])/len(groups[g]) for g in sorted(groups)
            ])),
        }
    return {
        "schema": "predict-shield/prospective-defense-audit/1",
        "status": "DESCRIPTIVE_ONLY_NOT_CONFIRMATORY_BY_ITSELF",
        "configuration_groups": len(partitions),
        "paired_episodes": len(arms),
        "policies": summaries,
        "ai_minus_expert_mean_group_cost": summaries["ai"]["mean_group_cost"] - summaries["expert"]["mean_group_cost"],
        "model_training_performed": False,
        "action_executed_by_auditor": False,
        "superiority_established": False,
        "critical_infrastructure_effectiveness_established": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arms", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Refusing to overwrite evidence")
    result = audit(json.loads(args.arms.read_text()), json.loads(args.decisions.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Wrote descriptive, read-only audit:", args.output)


if __name__ == "__main__":
    main()
