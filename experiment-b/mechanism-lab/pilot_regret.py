"""Audit a *measured* small pilot and compare engineering rules without training AI.

The small-pilot analysis reads actual separated records, not the generator's
planned outcomes. It requires every candidate action in every selected
configuration/repeat, and refuses missing oracle truth, missing time-integrated
gateway probes, invalid denominators or changed source provenance. No raw
oracle state or credential is included in its sanitized JSON report.

The hindsight-best action is calculated from separately executed replays.
This exploratory measure is descriptive, not a causal counterfactual or a
verified safety budget. Never present the small pilot as a trained AI result.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from audit import inspect_trial
from collect import load_plan
from decision_eval import (
    ACTIONS, SENSITIVITY_WEIGHTS, eligible_actions, engineering_rule,
    observed_utility,
)


def assess_pilot(plan_dir: Path, record_dir: Path, *,
                 selected_configs: tuple[str, ...]) -> dict:
    """Compare paired measured action costs under each preregistered weighting.

    The manifest is used solely for identity/provenance, not to supply
    outcome labels. The pilot must include two independent repetitions of
    each of the four actions for each named operating configuration.
    Source revisions must agree. Study-group bootstrap inference is NOT
    estimated from just three independently configured systems.
    """
    configs, trials = load_plan(plan_dir)
    expected = {c["configuration_id"] for c in configs}
    if not selected_configs or set(selected_configs) - expected:
        raise ValueError("Unregistered pilot configuration")
    selected = [t for t in trials
                if t["configuration_id"] in selected_configs and t["repeat"] in (0, 1)]
    if len(selected) != len(selected_configs) * 2 * len(ACTIONS):
        raise ValueError("Missing pilot replay registrations")
    records: dict[tuple[str, int], dict[str, dict]] = defaultdict(dict)
    source_revisions = set()
    for trial in selected:
        status, explanation = inspect_trial(trial, record_dir)
        if status != "complete":
            raise ValueError("Unverified measured replay: " + explanation)
        rid = trial["run_id"] + ".json"
        pre = json.loads((record_dir / "pre_action" / rid).read_text())
        verification = json.loads((record_dir / "verification" / rid).read_text())
        operations = json.loads((record_dir / "operations" / rid).read_text())
        oracle = json.loads((record_dir / "oracle" / rid).read_text())
        source_revisions.add(pre["source_commit"])
        timeline = verification.get("timed_gateway_exposure")
        if not timeline or timeline.get("valid_probe_count", 0) < 2:
            raise ValueError("Incomplete observed exposure timeline")
        observations = pre.get("external_deny_observations", [])
        if not observations:
            raise ValueError("Missing pre-action gateway observations")
        policy = pre.get("decision_policy_metadata", {})
        row = {
            "action": trial["action_id"],
            "pre_action": {
                "cache_ttl_ms": pre["features"]["cache_ttl_ms"],
                "initial_gateway_allowed_fraction": sum(
                    p.get("http_status") == 200 for p in observations
                ) / len(observations),
            },
            "restart_permitted": policy["restart_permitted"],
            "absolute_error_budget_requests": policy["absolute_error_budget_requests"],
            "label_path_exposure": timeline["exposure_fraction_upper_bound"],
            "label_security_exposure": float(
                not oracle["actual_revoked_access_denied"]),
            "label_absolute_failed_requests": operations["failed_requests"],
            "unknown_exposure_seconds": timeline["unknown_seconds"],
            "observed_requests": operations["observed_requests"],
            "verified_result": verification["outcome"],
        }
        records[(trial["configuration_id"], trial["repeat"])][trial["action_id"]] = row
    if len(source_revisions) != 1:
        raise ValueError("Mixed experiment source revisions")
    for actions in records.values():
        if set(actions) != set(ACTIONS):
            raise ValueError("Unpaired measured actions")
    if len(records) != 2 * len(selected_configs):
        raise ValueError("Missing repeated configuration groups")
    sensitivity = []
    for weighting in SENSITIVITY_WEIGHTS:
        result = Counter()
        regret = defaultdict(list)
        choice_counts = defaultdict(Counter)
        for actions in records.values():
            sample = next(iter(actions.values()))
            allowed = eligible_actions(sample)
            cost = {a: observed_utility(actions[a], weighting) for a in allowed}
            optimal = min(cost.values())
            selections = {
                "engineering_rule": engineering_rule(sample),
                "fixed_resync": "resync_policy",
                "fixed_restart_or_gateway": (
                    "restart_enforcer" if sample["restart_permitted"]
                    else "gateway_restrict"),
                "fixed_gateway": "gateway_restrict",
                "fixed_monitor": "monitor_only",
            }
            result.update(a for a, cost_value in cost.items()
                          if abs(cost_value - optimal) <= 1e-12)
            for name, action in selections.items():
                if action not in allowed:
                    raise ValueError("Engineering rule breached change freeze")
                regret[name].append(max(0.0, cost[action] - optimal))
                choice_counts[name][action] += 1
        sensitivity.append({
            "weights": dict(weighting),
            "policies": {
                name: {
                    "mean_hindsight_regret": sum(values) / len(values),
                    "action_counts": dict(choice_counts[name]),
                } for name, values in regret.items()
            },
            "hindsight_best_actions_including_ties": dict(result),
        })
    return {
        "schema": "predict-shield/repeated-small-pilot/1",
        "measured_runs": len(selected),
        "paired_decision_instances": len(records),
        "configuration_groups": len(selected_configs),
        "repeats_per_configuration": 2,
        "source_commit": next(iter(source_revisions)),
        "faults_included": sorted({
            c["fault_mode"] for c in configs
            if c["configuration_id"] in selected_configs
        }),
        "sensitivity": sensitivity,
        "uncertain_probe_time_seconds": sum(
            row["unknown_exposure_seconds"] for actions in records.values()
            for row in actions.values()
        ),
        "machine_learning_model_evaluated": False,
        "not_production_safety_or_causal_evidence": True,
    }


def main() -> None:
    """Write a sanitized, immutable pilot analysis from actual paired records."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--configurations", nargs="+", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    outcome = assess_pilot(args.plan, args.records,
                           selected_configs=tuple(args.configurations))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as out:
        json.dump(outcome, out, sort_keys=True, indent=2)
        out.write("\n")
    print(json.dumps(outcome, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
