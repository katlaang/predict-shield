"""Offline decision regret for actual timed Experiment B action replays.

The optimum is hindsight over distinct laboratory replays, not a causal
counterfactual or a production decision. The declared experimental restart
freeze masks actions at selection time, without hiding replay outcomes from
hindsight research. A declared absolute failed-request allowance is a cost
normalizer, not a measured *remaining* error budget or automatic authorization.

Research objective: 0.50 * time-integrated upper-bound path exposure fraction
                  + 0.25 * remaining control exposure indicator
                  + 0.25 * (absolute failed legitimate requests / budget).
The final term intentionally is NOT bounded at 1; exceeding the declared
budget remains visible rather than being capped into a convenient score.
"""
from __future__ import annotations

from collections import Counter, defaultdict

ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")
METRIC_WEIGHTS = {
    "label_path_exposure": 0.50,
    "label_security_exposure": 0.25,
    "label_absolute_failed_requests": 0.25,
}
SENSITIVITY_WEIGHTS = (
    METRIC_WEIGHTS,
    {"label_path_exposure": 0.70, "label_security_exposure": 0.20,
     "label_absolute_failed_requests": 0.10},
    {"label_path_exposure": 0.30, "label_security_exposure": 0.20,
     "label_absolute_failed_requests": 0.50},
)


def observed_utility(row: dict, weights: dict[str, float] = METRIC_WEIGHTS) -> float:
    """Score measured temporal exposure, unresolved control and absolute failure.

    Values must be nonnegative and exposure fractions no greater than one.
    The laboratory failure allowance is a fixed positive *count* per window,
    which keeps a costly restart expensive when absolute request failures
    rise with traffic. This is a research utility, not a safety permission.
    """
    if set(weights) != set(METRIC_WEIGHTS) or abs(sum(weights.values()) - 1) > 1e-8:
        raise ValueError("Unregistered objective weight components")
    budget = row.get("absolute_error_budget_requests")
    if type(budget) is not int or budget <= 0:
        raise ValueError("No declared absolute error allowance")
    for name in ("label_path_exposure", "label_security_exposure"):
        value = float(row[name])
        if not 0 <= value <= 1:
            raise ValueError("Invalid normalized exposure")
    failures = float(row["label_absolute_failed_requests"])
    if failures < 0 or failures != failures:
        raise ValueError("Invalid absolute failure observation")
    return (weights["label_path_exposure"] * float(row["label_path_exposure"])
            + weights["label_security_exposure"] * float(row["label_security_exposure"])
            + weights["label_absolute_failed_requests"] * failures / budget)


def engineering_rule(row: dict) -> str:
    """Choose a predeclared action without observing fault or future outcomes.

    If a revoked operation was observed allowed, prefer restart only when
    allowed by the independent research change policy and cache TTL exceeds
    six seconds. Otherwise restrict the protected gateway path (which
    preserves unrelated legitimate traffic in this fixture). If the gateway
    did not observe exposure, choose monitor-only. This rule is deliberately
    simple and may outperform a learned model.
    """
    pre = row["pre_action"]
    if pre["initial_gateway_allowed_fraction"] <= 0:
        return "monitor_only"
    if row["restart_permitted"] and pre["cache_ttl_ms"] > 6000:
        return "restart_enforcer"
    return "gateway_restrict"


def observable_telemetry_rule(row: dict) -> str:
    """Use a stronger prespecified *non-AI* rule with operational telemetry.

    Decisions depend on the gateway's observed allow fraction, real cache
    revision divergence, refresh-failure reports, measured cache age,
    requested load and explicit restart eligibility. They never use the
    fault-injection type, private oracle, future outcome or test labels.
    This comparator is deliberately stronger than a one-threshold rule;
    it is expected to tie or beat AI in some simple configurations.
    """
    pre = row["pre_action"]
    if pre["initial_gateway_allowed_fraction"] <= 0:
        return "monitor_only"
    divergence = pre.get("operator_revision_spread", 0)
    failures = pre.get("operator_refresh_failure_count", 0)
    age = pre.get("operator_max_cache_age_ms", 0)
    missing = pre.get("operator_missing_count", 0)
    if missing > 1:
        return "gateway_restrict"
    if not row["restart_permitted"]:
        return "gateway_restrict"
    if (divergence >= 1 or failures >= 1) and (
            pre["requested_rps"] <= 45 or age > pre["cache_ttl_ms"]):
        return "restart_enforcer"
    if pre["requested_rps"] > 45:
        return "gateway_restrict"
    return "resync_policy"


def eligible_actions(row: dict) -> tuple[str, ...]:
    """Screen candidates using declared change-freeze constraints only.

    Actual service-budget consumption must be measured and independently
    approved before a live policy gate authorizes action execution. Offline
    replay eligibility is NOT automatic authorization.
    """
    if type(row.get("restart_permitted")) is not bool:
        raise ValueError("Missing predeclared restart permission")
    return tuple(a for a in ACTIONS
                 if row["restart_permitted"] or a != "restart_enforcer")


def evaluate_regret(
    rows: list[dict],
    predictions: dict[tuple[str, int, str], dict[str, float]],
    weights: dict[str, float] = METRIC_WEIGHTS,
) -> dict:
    """Compare offline feasible model choices to human rules and fixed policies.

    Every configuration/repeat requires four measured counterfactual replays,
    even when a simulated change freeze would prohibit restarting in real
    deployment. Hindsight optimum and regret use measured outcome records
    only after all policies have selected actions from pre-action features
    and trained forecasts. The test data are not used to tune thresholds.
    """
    grouped = defaultdict(dict)
    for row in rows:
        key = (row["group"], row["repeat"])
        if row["action"] in grouped[key]:
            raise ValueError("Duplicate action replay")
        grouped[key][row["action"]] = row
    if not grouped:
        raise ValueError("No measured matched action groups")
    names = ("model", "engineer_rule", "observable_telemetry_rule", "fixed_resync",
             "fixed_restart_or_gateway", "fixed_gateway", "fixed_monitor")
    totals = {name: {"regret": [], "utility": [], "optimal_matches": 0,
                     "choices": Counter()} for name in names}
    optimal_choice_counts = Counter()
    for (group, repeat), observed in grouped.items():
        if set(observed) != set(ACTIONS):
            raise ValueError("Missing action replay from matched configuration")
        reference = next(iter(observed.values()))
        for other in observed.values():
            if (other["restart_permitted"] != reference["restart_permitted"]
                    or other["absolute_error_budget_requests"] !=
                    reference["absolute_error_budget_requests"]):
                raise ValueError("Different policy conditions in matched action set")
        allowed = eligible_actions(reference)
        true_cost = {a: observed_utility(observed[a], weights) for a in allowed}
        optimum = min(true_cost.values())
        optimal = {a for a, value in true_cost.items()
                   if abs(value - optimum) <= 1e-12}
        optimal_choice_counts.update(optimal)
        predicted_cost = {}
        for action in allowed:
            key = (group, repeat, action)
            if key not in predictions:
                raise ValueError("Missing held-out prediction")
            predicted_cost[action] = observed_utility(
                {**predictions[key],
                 "absolute_error_budget_requests":
                 reference["absolute_error_budget_requests"]}, weights)
        selected = {
            "model": min(allowed, key=lambda action: (predicted_cost[action], action)),
            "engineer_rule": engineering_rule(reference),
            "observable_telemetry_rule": observable_telemetry_rule(reference),
            "fixed_resync": "resync_policy",
            "fixed_restart_or_gateway": ("restart_enforcer"
                                         if reference["restart_permitted"]
                                         else "gateway_restrict"),
            "fixed_gateway": "gateway_restrict",
            "fixed_monitor": "monitor_only",
        }
        for name, action in selected.items():
            if action not in allowed:
                raise ValueError("An offline policy selected an ineligible action")
            item = totals[name]
            item["regret"].append(max(0.0, true_cost[action] - optimum))
            item["utility"].append(true_cost[action])
            item["optimal_matches"] += action in optimal
            item["choices"][action] += 1
    n = len(grouped)
    return {
        "schema": "predict-shield/offline-temporal-decision-regret/2",
        "weights": dict(weights),
        "decision_instances": n,
        "independent_configuration_groups": len({g for g, _ in grouped}),
        "policies": {
            name: {
                "mean_hindsight_regret": sum(item["regret"]) / n,
                "mean_observed_utility": sum(item["utility"]) / n,
                "optimal_match_fraction": item["optimal_matches"] / n,
                "action_selection_counts": dict(item["choices"]),
            } for name, item in totals.items()
        },
        "hindsight_optimal_action_counts_including_ties": dict(optimal_choice_counts),
        "evaluation_only": True,
        "actions_executed_by_model": False,
        "lab_budget_is_not_verified_remaining_error_budget": True,
    }


def evaluate_sensitivity(
    rows: list[dict],
    predictions: dict[tuple[str, int, str], dict[str, float]],
) -> list[dict]:
    """Report all three preregistered utility choices without choosing a winner.

    A model that gains under only one set of security/disruption weights has
    weaker evidence of robust decision improvement. Sensitivity calculations
    never alter the training split or the fitted model.
    """
    return [evaluate_regret(rows, predictions, weights=w)
            for w in SENSITIVITY_WEIGHTS]
