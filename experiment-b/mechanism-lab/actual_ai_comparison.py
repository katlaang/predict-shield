"""Train AND actually test an AI action selector on new measured Kafka/JVM trials.

This is an *exploratory*, configuration-held-out laboratory pilot, not an
automatically deployable defender or a confirmatory 20-group superiority proof.
No outcomes are synthesized. Train=12, calibration=6, test=6 independent
configurations, four physically replayed actions each, one repeat.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from collections import defaultdict
from pathlib import Path

from ai_comparison_plan import COUNTS, build, digest
from audit import inspect_trial
from decision_eval import (
    ACTIONS, eligible_actions, engineering_rule, observable_telemetry_rule,
    observed_utility, tune_rule_on_training_groups, tuned_rule_action,
)
from train import summarize_operator_telemetry, to_features

RULES = ("fixed_resync", "fixed_gateway", "fixed_monitor",
         "fixed_restart_or_gateway", "engineering_rule",
         "observable_telemetry_rule", "train_tuned_rule")
SEED = 2026111451


def read_measured(records: Path) -> tuple[list[dict], dict]:
    configs, trials = build()
    run_ids = {t["run_id"] for t in trials}
    if any(set(p.stem for p in (records / kind).glob("*.json")) != run_ids
           for kind in ("pre_action", "verification", "operations", "oracle")):
        raise ValueError("Four streams incomplete or unexpected records exist")
    data = defaultdict(dict)
    revisions = set()
    for trial in trials:
        state, reason = inspect_trial(trial, records)
        if state != "complete":
            raise ValueError("Cannot learn from incomplete physical record: " + reason)
        pre, verify, operations, oracle = [
            json.loads((records / kind / (trial["run_id"] + ".json")).read_text())
            for kind in ("pre_action", "verification", "operations", "oracle")]
        ]
        if (pre["oracle_features_excluded"] is not True or
                verify["verification_did_not_read_oracle"] is not True or
                pre["model_prediction_recorded"] is not False):
            raise ValueError("Oracle leakage contract failed")
        revisions.add(pre["source_commit"])
        exposure = verify["timed_gateway_exposure"]
        if exposure.get("method") != "monotonic_http_step_integral" or exposure["valid_probe_count"] < 2:
            raise ValueError("No real measured exposure")
        truth = oracle["after"]["all_revoked_access_denied"]
        if type(truth) is not bool or not oracle["after"]["inventory_complete"]:
            raise ValueError("No independently verified full-scope outcome")
        observed = operations["observed_requests"]
        failures = operations["failed_requests"]
        if not type(observed) is int or not type(failures) is int or not 0 <= failures <= observed or observed == 0:
            raise ValueError("Invalid actual failed-request count")
        group = pre["configuration_id"]
        action = trial["action_id"]
        if action in data[group]:
            raise ValueError("Duplicate physical action")
        # Keep oracle-derived labels SEPARATE from action-observable inputs.
        data[group][action] = {
            "pre": pre,
            "labels": {
                "label_path_exposure": float(exposure["exposure_fraction_upper_bound"]),
                "label_security_exposure": float(not truth),
                "label_absolute_failed_requests": float(failures),
            },
        }
    if len(revisions) != 1 or len(data) != 24 or any(set(arms) != set(ACTIONS) for arms in data.values()):
        raise ValueError("Mixed source revisions or missing paired configurations")
    rows = []
    for cfg in configs:
        group = cfg["configuration_id"]
        arms = data[group]
        # One common pre-action snapshot for ALL candidate comparisons in a
        # group. Avoid leaking which physical action replay had later outcomes.
        pre = arms["monitor_only"]["pre"]
        obs = pre["external_deny_observations"]
        if not obs or any(v.get("http_status") not in (200, 403) for v in obs):
            raise ValueError("No consistent real pre-action observation")
        features = {
            "cache_ttl_ms": pre["features"]["cache_ttl_ms"],
            "requested_rps": pre["features"]["requested_rps"],
            "gateway_visible_enforcer_count": pre["features"]["visible_enforcement_processes"],
            "initial_gateway_allowed_fraction": sum(x["http_status"] == 200 for x in obs) / len(obs),
            "routing_profile": pre["routing_profile"],
            **summarize_operator_telemetry(pre["operator_observations"]),
        }
        # Exclude hidden fault, target, delay and post-action values from model features.
        if set(features) & {"fault_mode", "fault_target", "event_delay_ms", "oracle", "post_action"}:
            raise ValueError("Future / fault information leaked into predictor")
        for action in ACTIONS:
            rows.append({
                "group": group, "partition": cfg["partition"], "repeat": 0,
                "action": action, "restart_permitted": cfg["restart_permitted"],
                "absolute_error_budget_requests": cfg["absolute_error_budget_requests"],
                "pre_action": features, **arms[action]["labels"],
            })
    return rows, {"source_commit_sha": next(iter(revisions)),
                  "registration_sha256": digest(configs, trials),
                  "executed_physical_action_replays": 96,
                  "independently_configured_groups": 24,
                  "four_streams_per_trial_verified": True,
                  "oracle_used_in_model_inputs": False}


def baseline_action(name: str, ref: dict, tuned: dict) -> str:
    choices = {
        "fixed_resync": "resync_policy",
        "fixed_gateway": "gateway_restrict",
        "fixed_monitor": "monitor_only",
        "fixed_restart_or_gateway":
            ("restart_enforcer" if ref["restart_permitted"] else "gateway_restrict"),
        "engineering_rule": engineering_rule(ref),
        "observable_telemetry_rule": observable_telemetry_rule(ref),
        "train_tuned_rule": tuned_rule_action(ref, tuned),
    }
    if name not in choices:
        raise ValueError("Unregistered deterministic comparator")
    result = choices[name]
    if result not in eligible_actions(ref):
        raise ValueError("Baseline selected prohibited action")
    return result


def evaluate(rows: list[dict], provenance: dict) -> dict:
    import numpy as np
    from sklearn.ensemble import RandomForestRegressor

    per_group = defaultdict(dict)
    for r in rows:
        g, action = r["group"], r["action"]
        if action in per_group[g]:
            raise ValueError("Duplicate action measurements")
        per_group[g][action] = r
    groups = {part: sorted(g for g in per_group if
                           next(iter(per_group[g].values()))["partition"] == part)
              for part in COUNTS}
    if {part: len(ids) for part, ids in groups.items()} != COUNTS:
        raise ValueError("Train/calibration/test group counts changed")
    if len(set().union(*map(set, groups.values()))) != 24:
        raise ValueError("Cross-partition group leakage")
    if any(set(arms) != set(ACTIONS) or
           len({x["partition"] for x in arms.values()}) != 1
           for arms in per_group.values()):
        raise ValueError("Missing measured physical action")
    labels = ("label_path_exposure", "label_security_exposure",
              "label_absolute_failed_requests")
    training = [per_group[g][a] for g in groups["train"] for a in ACTIONS]
    tuned = tune_rule_on_training_groups(training)["parameters"]
    feature_train = np.array([to_features(r) for r in training], dtype=float)
    models = {}
    for label in labels:
        model = RandomForestRegressor(n_estimators=160, min_samples_leaf=2,
                                      random_state=SEED, n_jobs=1)
        model.fit(feature_train, np.array([r[label] for r in training], dtype=float))
        models[label] = model
    def prediction(ref: dict, action: str) -> float:
        sample = {**ref, "action": action}
        vector = np.array([to_features(sample)], dtype=float)
        predicted = {key: max(0.0, float(model.predict(vector)[0]))
                     for key, model in models.items()}
        predicted["label_security_exposure"] = min(1.0, predicted["label_security_exposure"])
        predicted["label_path_exposure"] = min(1.0, predicted["label_path_exposure"])
        predicted["absolute_error_budget_requests"] = ref["absolute_error_budget_requests"]
        return observed_utility(predicted)
    def group_decisions(part: str):
        records = {}
        for group in groups[part]:
            arms = per_group[group]
            ref = arms["monitor_only"]
            permissible = eligible_actions(ref)
            measured = {a: observed_utility(arms[a]) for a in permissible}
            best = min(measured.values())
            comparison = {name: measured[baseline_action(name, ref, tuned)] - best
                          for name in RULES}
            if part == "test":
                forecast = {a: prediction(ref, a) for a in permissible}
                choice = min(permissible, key=lambda a: (forecast[a], a))
                comparison["ai"] = measured[choice] - best
                comparison["ai_selected_action"] = choice
                comparison["hindsight_optima"] = sorted(
                    a for a in permissible if measured[a] <= best + .001)
            records[group] = comparison
        return records
    calibration = group_decisions("calibration")
    cal_regrets = {name: sum(v[name] for v in calibration.values()) / len(calibration)
                   for name in RULES}
    locked = min(RULES, key=lambda name: (cal_regrets[name], name))
    heldout = group_decisions("test")
    group_ids = groups["test"]
    model_costs = [heldout[g]["ai"] for g in group_ids]
    baseline_costs = [heldout[g][locked] for g in group_ids]
    rng = random.Random(SEED)
    boot = []
    for _ in range(2000):
        selected = [rng.randrange(len(group_ids)) for _ in group_ids]
        boot.append(sum(baseline_costs[i] - model_costs[i] for i in selected) / len(selected))
    boot.sort()
    lower = boot[49]
    upper = boot[1949]
    baseline_mean = sum(baseline_costs) / len(group_ids)
    ai_mean = sum(model_costs) / len(group_ids)
    per_rule = {name: sum(heldout[g][name] for g in group_ids) / len(group_ids)
                for name in RULES}
    return {
        "schema": "predict-shield/real-physical-ai-vs-rule-exploratory-pilot/1",
        **provenance,
        "trained_model": "sklearn.RandomForestRegressor",
        "model_trained_on_real_physical_outcomes": True,
        "model_selected_actions_without_heldout_outcomes": True,
        "train_groups": len(groups["train"]),
        "calibration_groups": len(groups["calibration"]),
        "heldout_groups": len(groups["test"]),
        "locked_comparator_selected_using_calibration_only": locked,
        "calibration_comparator_regrets": cal_regrets,
        "test_ai_mean_hindsight_regret": ai_mean,
        "test_locked_rule_mean_hindsight_regret": baseline_mean,
        "heldout_paired_mean_regret_reduction": baseline_mean - ai_mean,
        "paired_group_bootstrap_regret_reduction_95": [lower, upper],
        "ai_better_than_locked_baseline_in_these_test_groups":
            ai_mean < baseline_mean,
        "ai_improvement_interval_excludes_zero": lower > 0,
        "heldout_per_comparator_mean_regret": per_rule,
        "test_group_decisions": [{
            "configuration_id": g,
            "ai_selected_action": heldout[g]["ai_selected_action"],
            "hindsight_optimal_actions": heldout[g]["hindsight_optima"],
            "ai_regret": heldout[g]["ai"],
            "locked_baseline_regret": heldout[g][locked],
        } for g in group_ids],
        "exploratory_only_not_superiority_proof": True,
        "minimum_independent_heldout_groups_for_confirmatory_claim_not_met": True,
        "critical_infrastructure_field_evidence": False,
        "no_automatic_action_execution_by_ai": True,
        "not_original_frozen_v3_or_full_v31_campaign": True,
        "limitations": [
            "Only six independently configured heldout groups, not the twenty required for the existing full-campaign decision audit",
            "One physical replay per action and configuration, so measurement variance and action carryover remain concerns",
            "Chosen subset uses earlier inspected fault mechanisms; not an uninspected external population",
            "Action supervision uses post-action oracle only for labels, never pre-action model features",
            "A model can outperform one calibrated baseline yet lose to another: report all seven comparators",
            "No external infrastructure trial, prospective confirmation or deployment authorization",
        ],
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--records", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    rows, provenance = read_measured(a.records)
    report = evaluate(rows, provenance)
    a.report.parent.mkdir(parents=True, exist_ok=True)
    with a.report.open("x", encoding="utf8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps({
        "actual_physical_replays": report["executed_physical_action_replays"],
        "trained_on_actual_measurements": True,
        "independent_test_groups": report["heldout_groups"],
        "ai_mean_regret": report["test_ai_mean_hindsight_regret"],
        "locked_rule_mean_regret": report["test_locked_rule_mean_hindsight_regret"],
        "mean_improvement": report["heldout_paired_mean_regret_reduction"],
        "group_bootstrap_95": report["paired_group_bootstrap_regret_reduction_95"],
        "confirmatory_superiority_established": False,
    }))


if __name__ == "__main__":
    main()
