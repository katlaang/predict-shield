"""Decision-level evaluation of learned action selection against real playbooks.

This module is intentionally OFFLINE. It cannot dispatch security actions.
It joins four already-executed counterfactual action replays for each registered
configuration and repeat, then compares what different decision policies
*would have selected* from pre-action information. The hindsight optimum uses
actual measured outcomes only to score regret, never to choose the model or
engineering-rule action.

Counterfactual outcomes are separate replays, not simultaneous outcomes under
identical network scheduling. Regret is descriptive for this laboratory;
causal/generalizable policy improvement is not demonstrated by this report.
"""
from __future__ import annotations

from collections import Counter, defaultdict

ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")
METRIC_WEIGHTS = {
    "label_path_exposure": 0.50,
    "label_security_exposure": 0.25,
    "label_service_failure_fraction": 0.25,
}


def observed_utility(row: dict) -> float:
    """Calculate a preregistered three-outcome cost from observed measurements.

    A zero value is best; exposure and disruption fractions must remain in
    [0, 1]. This scoring convention is explicitly experimental, not a policy
    authorization or evidence that another objective would yield the same
    action ordering.
    """
    score = 0.0
    for target, weight in METRIC_WEIGHTS.items():
        value = float(row[target])
        if not 0 <= value <= 1:
            raise ValueError("Observed outcome outside normalized metric bounds")
        score += weight * value
    return score


def engineering_rule(row: dict) -> str:
    """Choose an action using observable conditions and no hidden fault labels.

    Predeclared conservative heuristic: if access is still allowed at the
    gateway and configured TTL exceeds six seconds, restart the affected
    enforcement process (subject to separate action approval and budgets);
    otherwise resynchronize policy. This is a fixed engineering comparator,
    not proof that such a rule is production safe.
    """
    pre = row["pre_action"]
    if (pre["initial_gateway_allowed_fraction"] > 0
            and pre["cache_ttl_ms"] > 6000):
        return "restart_enforcer"
    return "resync_policy"


def evaluate_regret(
    rows: list[dict],
    predictions: dict[tuple[str, int, str], dict[str, float]],
) -> dict:
    """Compare offline model ranking with fixed and engineering playbooks.

    Every decision group must contain all four measured action replays.
    Predicted labels must come from models trained on disjoint training groups.
    A model can never use test oracle outcomes or post-action observations as
    selection input. A decision with missing estimates is refused, not imputed.
    """
    grouped = defaultdict(dict)
    for row in rows:
        key = (row["group"], row["repeat"])
        if row["action"] in grouped[key]:
            raise ValueError("Duplicate candidate in decision group")
        grouped[key][row["action"]] = row
    if not grouped:
        raise ValueError("No held-out decision groups")
    policy_names = ("model", "engineer_rule", "fixed_resync", "fixed_restart",
                    "fixed_gateway", "fixed_monitor")
    totals = {name: {"regret": [], "utility": [], "oracle_match": 0,
                     "choices": Counter()} for name in policy_names}
    for (config, repeat), observed in grouped.items():
        if set(observed) != set(ACTIONS):
            raise ValueError("Missing matched-action observation")
        sample = next(iter(observed.values()))
        actual = {action: observed_utility(value)
                  for action, value in observed.items()}
        optimum = min(actual.values())
        best = {a for a, v in actual.items() if abs(v - optimum) <= 1e-12}
        forecast = {}
        for action in ACTIONS:
            key = (config, repeat, action)
            if key not in predictions:
                raise ValueError("Prediction missing for held-out candidate")
            forecast[action] = observed_utility(predictions[key])
        choice = {
            "model": min(ACTIONS, key=lambda x: (forecast[x], x)),
            "engineer_rule": engineering_rule(sample),
            "fixed_resync": "resync_policy",
            "fixed_restart": "restart_enforcer",
            "fixed_gateway": "gateway_restrict",
            "fixed_monitor": "monitor_only",
        }
        for name, action in choice.items():
            row = totals[name]
            row["choices"][action] += 1
            row["regret"].append(max(0.0, actual[action] - optimum))
            row["utility"].append(actual[action])
            row["oracle_match"] += action in best
    n = len(grouped)
    return {
        "schema": "predict-shield/offline-decision-regret/1",
        "registered_objective_weights": METRIC_WEIGHTS,
        "decision_instances": n,
        "independent_configuration_groups": len({config for config, _ in grouped}),
        "policies": {
            name: {
                "mean_hindsight_regret": sum(item["regret"]) / n,
                "mean_observed_utility": sum(item["utility"]) / n,
                "oracle_optimal_action_match_fraction": item["oracle_match"] / n,
                "action_selection_counts": dict(item["choices"]),
            }
            for name, item in totals.items()
        },
        "evaluation_only": True,
        "actions_executed_by_model": False,
        "operational_error_budget_enforced": False,
        "limitations": [
            "Replay-level hindsight optimum is not a causal counterfactual",
            "Prediction error and regret cannot establish operational safety",
            "Objective weights were fixed before assessing test-set outcomes",
            "The fixed engineer rule and playbooks require separate safety authorization",
        ],
    }
