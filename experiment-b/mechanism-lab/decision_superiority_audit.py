"""Held-out AI action-decision value versus calibration-locked strong rules.

All action costs are measured physical replay outcomes supplied by the existing
four-stream executed-data loader. No synthetic labels, oracle data in features,
deployment approval, or results are created by this module.

Select the strongest non-AI comparator on CALIBRATION groups and evaluate it
unchanged against AI on disjoint TEST groups, with a group-paired bootstrap.
"""
from __future__ import annotations

import math
import random
from collections import defaultdict

from decision_eval import (
    ACTIONS, eligible_actions, engineering_rule, observable_telemetry_rule,
    observed_utility, tuned_rule_action,
)

COMPARATOR_NAMES = (
    "observable_telemetry_rule", "engineering_rule", "train_tuned_rule",
    "fixed_resync", "fixed_restart_or_gateway", "fixed_gateway", "fixed_monitor",
)
REPLICATES = 2000
BOOTSTRAP_SEED = 20261114
MIN_TEST_GROUPS_FOR_CLAIM = 20
RELATIVE_IMPROVEMENT_TARGET = 0.10


def baseline_action(name: str, reference: dict, tuned_parameters: dict) -> str:
    allowed = eligible_actions(reference)
    if reference.get("fault") == "authority_outage":
        # The separate v3.1 outage condition does not have a common
        # authoritative scalar outcome. Never silently assign it one.
        raise ValueError("Cannot score UNKNOWN authority-outage truth as point utility")
    choices = {
        "observable_telemetry_rule": observable_telemetry_rule(reference),
        "engineering_rule": engineering_rule(reference),
        "train_tuned_rule": tuned_rule_action(reference, tuned_parameters),
        "fixed_resync": "resync_policy",
        "fixed_restart_or_gateway": (
            "restart_enforcer" if reference["restart_permitted"] else "gateway_restrict"),
        "fixed_gateway": "gateway_restrict",
        "fixed_monitor": "monitor_only",
    }
    if name not in choices:
        raise ValueError("Unknown comparator")
    action = choices[name]
    if action not in allowed:
        raise ValueError("Comparator selected ineligible action")
    return action


def _paired(rows: list[dict], predictions: dict,
            tuned_parameters: dict, *, partition: str) -> dict[str, dict]:
    selected = [r for r in rows if r.get("partition") == partition]
    if not selected:
        raise ValueError("No measured paired rows in " + partition)
    by_key = defaultdict(dict)
    for row in selected:
        key = (row["group"], row["repeat"])
        action = row["action"]
        if action not in ACTIONS or action in by_key[key]:
            raise ValueError("Duplicate/unregistered physical action")
        by_key[key][action] = row
    by_group = defaultdict(list)
    for (group, repeat), arms in by_key.items():
        if set(arms) != set(ACTIONS):
            raise ValueError("Incomplete four-arm physical replay group")
        reference = arms[ACTIONS[0]]
        allowed = eligible_actions(reference)
        for arm in arms.values():
            if (arm["restart_permitted"] != reference["restart_permitted"] or
                    arm["absolute_error_budget_requests"] !=
                    reference["absolute_error_budget_requests"] or
                    arm.get("partition") != partition or
                    arm.get("fault") == "authority_outage"):
                raise ValueError("Inconsistent or UNKNOWN physical group")
        true_cost = {a: observed_utility(arms[a]) for a in allowed}
        best = min(true_cost.values())
        costs = {name: true_cost[baseline_action(name, reference, tuned_parameters)] - best
                 for name in COMPARATOR_NAMES}
        if partition == "test":
            predicted = {}
            for action in allowed:
                key = (group, repeat, action)
                if key not in predictions:
                    raise ValueError("Missing blinded held-out action forecast")
                predicted[action] = observed_utility({
                    **predictions[key],
                    "absolute_error_budget_requests":
                        reference["absolute_error_budget_requests"],
                })
            chosen = min(allowed, key=lambda a: (predicted[a], a))
            costs["ai_model"] = true_cost[chosen] - best
        by_group[group].append(costs)
    count_by_group = {g: len(v) for g, v in by_group.items()}
    if set(count_by_group.values()) != {3}:
        raise ValueError("Expected exactly three independent physical repetitions per configuration")
    if len(by_group) < 2:
        raise ValueError("Too few independent physical configurations")
    return {g: {policy: sum(x[policy] for x in items) / len(items)
                for policy in items[0]}
            for g, items in by_group.items()}


def _quantile(sorted_values: list[float], p: float) -> float:
    position = (len(sorted_values)-1)*p
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    return (sorted_values[lower]*(upper-position) +
            sorted_values[upper]*(position-lower))


def evaluate(rows: list[dict], heldout_predictions: dict,
             tuned_parameters: dict, *, seed: int = BOOTSTRAP_SEED,
             replicates: int = REPLICATES) -> dict:
    if not 500 <= replicates <= 5000:
        raise ValueError("Group bootstrap requires 500-5000 replicates")
    calibration = _paired(rows, {}, tuned_parameters, partition="calibration")
    test = _paired(rows, heldout_predictions, tuned_parameters, partition="test")
    if set(calibration) & set(test):
        raise ValueError("Calibration and held-out configuration leakage")
    if set(calibration) & {r["group"] for r in rows
                          if r["partition"] == "train"} or (
            set(test) & {r["group"] for r in rows if r["partition"] == "train"}):
        raise ValueError("Training group leakage")
    # No test labels may select the comparator.
    cal_scores = {name: sum(v[name] for v in calibration.values())/len(calibration)
                  for name in COMPARATOR_NAMES}
    locked = min(COMPARATOR_NAMES, key=lambda n: (cal_scores[n], n))
    test_groups = sorted(test)
    baseline = [test[g][locked] for g in test_groups]
    model = [test[g]["ai_model"] for g in test_groups]
    n = len(test_groups)
    observed_baseline = sum(baseline)/n
    observed_model = sum(model)/n
    deltas = [base - learned for base, learned in zip(baseline, model)]
    rng = random.Random(seed)
    absolute, relative = [], []
    for _ in range(replicates):
        idx = [rng.randrange(n) for _ in range(n)]
        b = sum(baseline[i] for i in idx)/n
        m = sum(model[i] for i in idx)/n
        absolute.append(b-m)
        # A zero-regret baseline leaves no measurable headroom.
        relative.append((b-m)/b if b > 1e-12 else None)
    absolute.sort()
    ci_absolute = [_quantile(absolute, .025), _quantile(absolute, .975)]
    # If even one bootstrap draw has zero baseline regret, there is no
    # well-defined relative improvement interval under the registered metric.
    ci_relative = None if any(v is None for v in relative) else [
        _quantile(sorted(relative), .025), _quantile(sorted(relative), .975)]
    is_sufficient = len(test) >= MIN_TEST_GROUPS_FOR_CLAIM
    target_met = (is_sufficient and observed_baseline > 1e-12
                  and ci_relative is not None
                  and ci_relative[0] > RELATIVE_IMPROVEMENT_TARGET)
    other_rules = {name: sum(test[g][name] for g in test_groups)/n
                   for name in COMPARATOR_NAMES}
    return {
        "schema": "predict-shield/heldout-ai-decision-superiority-audit/1",
        "heldout_group_count": n,
        "calibration_group_count": len(calibration),
        "independent_test_unit": "physical_operating_configuration",
        "non_ai_comparator_locked_by": "calibration_group_regret_only",
        "locked_non_ai_comparator": locked,
        "calibration_non_ai_regret": cal_scores,
        "heldout_non_ai_comparator_regret": other_rules,
        "heldout_model_mean_regret": observed_model,
        "heldout_locked_baseline_mean_regret": observed_baseline,
        "heldout_paired_mean_regret_improvement": sum(deltas)/n,
        "paired_group_bootstrap_absolute_95": ci_absolute,
        "paired_group_bootstrap_relative_95": ci_relative,
        "relative_improvement_target": RELATIVE_IMPROVEMENT_TARGET,
        "improvement_target_supported_in_lab": target_met,
        "research_status": (
            "LAB_HELDOUT_SUPERIORITY_SUPPORTED_WITH_LIMITATIONS"
            if target_met else "LAB_SUPERIORITY_NOT_ESTABLISHED"),
        "no_automatic_action_execution": True,
        "no_external_critical_infrastructure_validation": True,
        "no_causal_generalization_or_niw_approval_claim": True,
        "source_requirement": "independently audited real Kafka/JVM four-stream records",
        "bootstrap_seed": seed,
        "bootstrap_replicates": replicates,
        "limitations": [
            "Historical calibration may adapt to lab; test is disjoint by configuration",
            "Physical action replays are not perfect causal counterfactuals",
            "Bootstrap assumes independent operating configurations",
            "Compared against a calibration-selected non-AI baseline, not a random strawman",
            "No authority-outage UNKNOWN truth is converted into a scalar label",
            "Positive lab superiority cannot establish field performance",
        ],
    }
