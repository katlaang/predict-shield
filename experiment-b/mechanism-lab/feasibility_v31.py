"""Exploratory v3.1 action-diversity / precision feasibility gate.

Consumes independently audited *measured* records only. This gate does not
select difficulty based on model performance, train an AI model, or authorize
a 1,200-trial campaign. Valid output can be FEASIBILITY_INCONCLUSIVE.
"""
from __future__ import annotations

import argparse
import json
import math
import random
from collections import defaultdict
from pathlib import Path

ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")
TOLERANCE = 0.001
DIVERSITY_THRESHOLD = 0.30
REQUIRED_PV_OPTIMA = 2
BOOTSTRAP_SEED = 20261112
BOOTSTRAP_REPLICATES = 2000


def _percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * p
    left = math.floor(position)
    right = math.ceil(position)
    return ordered[left] * (right - position) + ordered[right] * (position - left) if left != right else ordered[left]


def evaluate(records: list[dict], *, fixed_action: str = "resync_policy") -> dict:
    """Measure action headroom and cluster-level uncertainty.

    Every row is one independent configuration/repeat with four completed,
    independently scored action replays. The paired utility values must have
    been computed using the locked primary utility definition. This function
    cannot itself attest external provenance; caller must audit raw records.
    """
    if fixed_action not in ACTIONS:
        raise ValueError("Fixed comparator must be registered before pilot")
    if not records:
        raise ValueError("No measured pilot records")
    groups = defaultdict(list)
    source_commits = set()
    for r in records:
        if r.get("schema") != "predict-shield/v31-audited-action-costs/1":
            raise ValueError("Unrecognized audited cost schema")
        if r.get("measurement_verified") is not True or not r.get("four_streams_complete"):
            raise ValueError("Not independently audited measured replay")
        if r.get("partition") != "pilot":
            raise ValueError("Feasibility cannot inspect training, calibration or test outcomes")
        commit = r.get("source_commit")
        if not isinstance(commit, str) or len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
            raise ValueError("Missing source commit")
        source_commits.add(commit)
        eligible = r.get("eligible_actions")
        costs = r.get("action_costs")
        if not isinstance(eligible, list) or len(set(eligible)) != len(eligible) or not set(eligible).issubset(ACTIONS):
            raise ValueError("Invalid action eligibility")
        if fixed_action not in eligible:
            raise ValueError("Fixed comparator ineligible; prespecify eligible policy fallback")
        if not isinstance(costs, dict) or set(costs) != set(ACTIONS):
            raise ValueError("Every action must be measured")
        if any(type(v) not in (float, int) or not math.isfinite(v) or v < 0 for v in costs.values()):
            raise ValueError("Invalid measured cost")
        if r.get("stratum") not in ("SIMPLE", "INTERACTION", "PARTIAL_VISIBILITY"):
            raise ValueError("Unregistered difficulty stratum")
        if type(r.get("repeat")) is not int or r["repeat"] not in (0, 1):
            raise ValueError("Exactly two registered repeats required")
        ident = r.get("configuration_id")
        if not isinstance(ident, str) or not ident.startswith("v31-pilot-"):
            raise ValueError("Unregistered independent pilot group")
        groups[ident].append(r)
    if len(source_commits) != 1:
        raise ValueError("Mixed source revisions")
    if len(groups) < 3:
        raise ValueError("At least three independent pilot configurations required")
    mismatch_count = 0
    instance_count = 0
    pv_unique = set()
    group_regrets = []
    group_summary = []
    for ident, rows in sorted(groups.items()):
        if len(rows) != 2 or {x["repeat"] for x in rows} != {0, 1}:
            raise ValueError("Missing or duplicate paired repeats")
        if len({x["stratum"] for x in rows}) != 1:
            raise ValueError("Difficulty varied within paired configuration")
        instance_regret = []
        for row in rows:
            costs = row["action_costs"]
            allowed = row["eligible_actions"]
            optimal = min(costs[a] for a in allowed)
            best = {a for a in allowed if costs[a] - optimal <= TOLERANCE}
            mismatch_count += fixed_action not in best
            instance_count += 1
            instance_regret.append(max(0.0, costs[fixed_action] - optimal))
            if row["stratum"] == "PARTIAL_VISIBILITY" and len(best) == 1:
                pv_unique.update(best)
        group_regrets.append(sum(instance_regret) / 2)
        group_summary.append({"configuration_id": ident,
                              "stratum": rows[0]["stratum"],
                              "fixed_mean_regret": group_regrets[-1]})
    mean_regret = sum(group_regrets) / len(group_regrets)
    rng = random.Random(BOOTSTRAP_SEED)
    means = [sum(rng.choice(group_regrets) for _ in group_regrets) / len(group_regrets)
             for _ in range(BOOTSTRAP_REPLICATES)]
    lo, hi = _percentile(means, .025), _percentile(means, .975)
    target = .10 * mean_regret
    half_width = (hi - lo) / 2
    diversity = mismatch_count / instance_count
    failures = []
    if diversity < DIVERSITY_THRESHOLD:
        failures.append("insufficient_fixed_policy_decision_diversity")
    if len(pv_unique) < REQUIRED_PV_OPTIMA:
        failures.append("insufficient_unique_partial_visibility_optimal_actions")
    # The spread of *fixed-vs-oracle* regret is a feasibility diagnostic,
    # NOT the sampling variance of a future trained-model paired improvement.
    if mean_regret <= 0 or half_width > target:
        failures.append("oracle_gap_precision_diagnostic_inconclusive")
    return {"schema": "predict-shield/v31-feasibility-diagnostic/1",
            "status": "FEASIBILITY_INCONCLUSIVE" if failures else "EXPLORATORY_GATES_PASSED_NOT_CAMPAIGN_AUTHORIZATION",
            "source_commit": next(iter(source_commits)),
            "pilot_configuration_groups": len(groups),
            "paired_decision_instances": instance_count,
            "fixed_action": fixed_action,
            "tie_tolerance": TOLERANCE,
            "mismatched_decisions": mismatch_count,
            "decision_diversity": diversity,
            "minimum_diversity": DIVERSITY_THRESHOLD,
            "partial_visibility_unique_optima": sorted(pv_unique),
            "fixed_policy_mean_hindsight_regret": mean_regret,
            "fixed_vs_oracle_group_bootstrap_95pct": [lo, hi],
            "half_width": half_width,
            "hypothetical_10pct_fixed_regret": target,
            "precision_not_a_model_power_calculation": True,
            "failures": failures,
            "per_group": group_summary,
            "trained_ai_evaluated": False}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--audited-records", required=True)
    p.add_argument("--fixed-action", default="resync_policy")
    p.add_argument("--output", required=True)
    a = p.parse_args()
    records = [json.loads(x) for x in Path(a.audited_records).read_text().splitlines() if x.strip()]
    result = evaluate(records, fixed_action=a.fixed_action)
    out = Path(a.output)
    with out.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(result["status"])


if __name__ == "__main__":
    main()
