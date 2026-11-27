"""Read-only paired lab defense evaluation.

Uses measured four-action experimental arms, exposing only pre-action
operator observations to the learned chooser. It never dispatches actions,
relabels old experiments as prospective, or turns missing outcomes into success.

The 1,200-trial historical campaign is *development evidence*, not a fresh
confirmatory evaluation for a selector derived from that campaign.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from types import MappingProxyType
from typing import Callable

from action_utility import observed_utility
from train import ACTIONS, OPERATOR_FEATURES, ROUTING_PROFILES, to_features

REQUIRED_PRE = (
    "cache_ttl_ms", "requested_rps", "gateway_visible_enforcer_count",
    "initial_gateway_allowed_fraction", "routing_profile",
)
ALLOWED_PRE = set(REQUIRED_PRE) | set(OPERATOR_FEATURES)
LABELS = (
    "label_path_exposure", "label_security_exposure",
    "label_absolute_failed_requests",
)
PARTITIONS = {"train", "calibration", "test"}


def _finite(number):
    return type(number) in (int, float) and math.isfinite(number)


def _preaction(pre):
    if not isinstance(pre, dict) or set(pre) - ALLOWED_PRE:
        raise ValueError("Unknown pre-action fields: possible future/oracle leakage")
    if not set(REQUIRED_PRE).issubset(pre):
        raise ValueError("Missing operator-observable pre-action features")
    if pre["routing_profile"] not in ROUTING_PROFILES:
        raise ValueError("Unregistered routing profile")
    if any(not _finite(value) for name, value in pre.items()
           if name != "routing_profile"):
        raise ValueError("Non-finite pre-action observation")
    if not 0 <= pre["initial_gateway_allowed_fraction"] <= 1:
        raise ValueError("Invalid initial gateway observation")


def _validate_and_pair(rows):
    if not isinstance(rows, list) or not rows:
        raise ValueError("No measured defense observations")
    groups = defaultdict(dict)
    partitions = {}
    for r in rows:
        if not isinstance(r, dict):
            raise ValueError("Malformed measured action record")
        group, repeat, action, part = (
            r.get("group"), r.get("repeat"), r.get("action"), r.get("partition")
        )
        if not isinstance(group, str) or not group or type(repeat) is not int or repeat < 0:
            raise ValueError("Invalid independent configuration or repeat identifier")
        if part not in PARTITIONS or action not in ACTIONS:
            raise ValueError("Invalid partition/action label")
        if group in partitions and partitions[group] != part:
            raise ValueError("Configuration crosses train/calibration/test partitions")
        partitions[group] = part
        key = (group, repeat)
        if action in groups[key]:
            raise ValueError("Duplicate measured action")
        if type(r.get("restart_permitted")) is not bool:
            raise ValueError("Unknown restart authorization")
        budget = r.get("absolute_error_budget_requests")
        if type(budget) is not int or budget < 1:
            raise ValueError("No trusted positive disruption allowance")
        _preaction(r.get("pre_action"))
        if any(not _finite(r.get(label)) for label in LABELS):
            raise ValueError("Missing or non-finite independent observed outcome")
        if any(not 0 <= r[name] <= 1 for name in LABELS[:2]):
            raise ValueError("Out-of-range observed exposure")
        if r["label_absolute_failed_requests"] < 0:
            raise ValueError("Impossible negative failed requests")
        groups[key][action] = r

    for key, arm in groups.items():
        if set(arm) != set(ACTIONS):
            raise ValueError(f"Incomplete paired four-action outcome: {key}")
        if len({x["partition"] for x in arm.values()}) != 1:
            raise ValueError("Mismatched partition within an action pairing")
        if len({x["restart_permitted"] for x in arm.values()}) != 1:
            raise ValueError("Mismatched authorization between matched replays")
        if len({x["absolute_error_budget_requests"] for x in arm.values()}) != 1:
            raise ValueError("Mismatched disruption budgets between replays")
    return groups


def _eligible(restart_permitted):
    return tuple(a for a in ACTIONS if a != "restart_enforcer" or restart_permitted)


def _score(row):
    return observed_utility(row)


def _baseline(name, eligible):
    if name == "monitor_only":
        return "monitor_only"
    if name == "resync_policy":
        return "resync_policy"
    if name == "restart_if_allowed":
        return "restart_enforcer" if "restart_enforcer" in eligible else "monitor_only"
    raise ValueError("Unknown fixed-policy baseline")


def make_trusted_lab_model_policy(bundle: dict) -> Callable:
    """Use trusted local model estimates; never pass oracle truth to selector.

    All policy decisions are recommendations in a disposable lab only.
    This does not call the executor or bypass the actual typed safety gate.
    """
    if (bundle.get("schema") != "predict-shield/mechanism-model-bundle/1"
            or bundle.get("training_group_count") != 60
            or bundle.get("calibration_group_count") != 20
            or bundle.get("not_certified_for_automatic_execution") is not True):
        raise ValueError("Bundle is not an eligible calibrated lab-only model")
    models = bundle.get("models")
    bounds = bundle.get("numeric_feature_bounds")
    if not isinstance(models, dict) or not isinstance(bounds, dict):
        raise ValueError("Model estimates or OOD bounds missing")
    if any(label not in models for label in LABELS):
        raise ValueError("Model does not predict all outcome dimensions")
    for feature in REQUIRED_PRE[:-1]:
        if feature not in bounds or len(bounds[feature]) != 2:
            raise ValueError("Incomplete trusted bounds for feature " + feature)

    def choose(context: dict, eligible: tuple[str, ...]) -> str | None:
        pre = context["pre_action"]
        _preaction(pre)
        # The offline policy abstains on unseen operating conditions.
        for feature, (lo, hi) in bounds.items():
            if feature == "routing_profile":
                continue
            if feature not in pre or not _finite(pre[feature]):
                return None
            if not _finite(lo) or not _finite(hi) or not lo <= pre[feature] <= hi:
                return None
        budget = context["absolute_error_budget_requests"]
        estimates = {}
        for action in eligible:
            vector = [to_features({"pre_action": pre, "action": action})]
            try:
                path, security, failures = (
                    float(models[name].predict(vector)[0]) for name in LABELS
                )
            except (ValueError, IndexError, TypeError, KeyError):
                return None
            if not all(map(_finite, (path, security, failures))):
                return None
            # Predictions may overshoot physical bounds. Clip only for
            # ranking; never interpret this as a verified risk estimate.
            path, security, failures = (
                max(0., min(1., path)), max(0., min(1., security)),
                max(0., failures),
            )
            estimates[action] = 0.5 * path + 0.25 * security + 0.25 * failures / budget
        return min(eligible, key=lambda action: (estimates[action], ACTIONS.index(action)))
    return choose


def evaluate_paired(rows: list[dict], choose: Callable, *,
                    model_fingerprint: str, dataset_fingerprint: str,
                    partition: str = "test") -> dict:
    """Descriptive regret against hindsight-best *per matched configuration*.

    The caller chooses a model before seeing held-out results. No tuning or
    model training occurs here. 'Oracle best' is analysis-only, not a policy.
    """
    if partition != "test":
        raise ValueError("Only sealed test partition may be evaluated")
    for name, value in (("model", model_fingerprint), ("measured dataset", dataset_fingerprint)):
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("Missing pinned " + name + " SHA-256")
    pairs = _validate_and_pair(rows)
    test = {key: arm for key, arm in pairs.items() if arm["monitor_only"]["partition"] == partition}
    if not test:
        raise ValueError("No held-out test configurations")
    by_policy = defaultdict(lambda: defaultdict(list))
    abstentions = Counter()
    policy_violations = Counter()
    evidence = []
    for (group, repeat), arms in sorted(test.items()):
        base = arms["monitor_only"]
        eligible = _eligible(base["restart_permitted"])
        # The chooser gets ONLY a copied pre-action projection from a
        # canonical monitor-only replay, never the outcomes of any arm.
        context = {
            "pre_action": dict(base["pre_action"]),
            "restart_permitted": base["restart_permitted"],
            "absolute_error_budget_requests": base["absolute_error_budget_requests"],
        }
        picked = choose(MappingProxyType(context), eligible)
        if picked not in eligible:
            if picked is None:
                abstentions["learned_policy"] += 1
            else:
                policy_violations["learned_policy"] += 1
            picked = "monitor_only"  # Explicit safe evaluation fallback, not free cost.
        action_costs = {action: _score(arms[action]) for action in eligible}
        oracle_best = min(action_costs.values())
        choices = {
            "learned_policy": picked,
            **{name: _baseline(name, eligible) for name in
               ("monitor_only", "resync_policy", "restart_if_allowed")},
        }
        for name, action in choices.items():
            row = arms[action]
            cost = action_costs[action]
            ent = by_policy[name][group]
            ent.append({"cost": cost, "regret": cost - oracle_best,
                        "success": row["label_security_exposure"] == 0,
                        "action": action,
                        "service_failures": row["label_absolute_failed_requests"]})
        evidence.append({
            "configuration_id": group, "repeat": repeat, "allowed_actions": list(eligible),
            "selected_actions": choices, "oracle_best_cost_analysis_only": oracle_best,
        })
    report_policies = {}
    for name, groups in by_policy.items():
        means = [{
            "configuration_id": group,
            "mean_cost": sum(r["cost"] for r in v)/len(v),
            "mean_regret": sum(r["regret"] for r in v)/len(v),
            "successful_replays": sum(r["success"] for r in v),
            "replays": len(v),
            "failed_legitimate_requests": sum(r["service_failures"] for r in v),
        } for group, v in sorted(groups.items())]
        report_policies[name] = {
            "configuration_groups": len(groups),
            "paired_replays": sum(len(v) for v in groups.values()),
            "mean_configuration_cost": sum(x["mean_cost"] for x in means)/len(means),
            "mean_configuration_regret": sum(x["mean_regret"] for x in means)/len(means),
            "successful_replays": sum(x["successful_replays"] for x in means),
            "failed_legitimate_requests": sum(x["failed_legitimate_requests"] for x in means),
            "per_configuration": means,
            "abstentions": abstentions[name],
            "prohibited_recommendations": policy_violations[name],
        }
    return {
        "schema": "predict-shield/offline-paired-defense-comparison/1",
        "status": "EXPLORATORY_HISTORICAL_ONLY",
        "model_fingerprint_sha256": model_fingerprint,
        "measured_dataset_sha256": dataset_fingerprint,
        "partition": partition,
        "configuration_groups": len({key[0] for key in test}),
        "paired_replays": len(test),
        "policies": report_policies,
        "choices": evidence,
        "execution_performed": False,
        "production_effectiveness_established": False,
        "prospective_superiority_established": False,
        "limitations": [
            "Previous test groups and campaigns were already examined; not new confirmatory evidence",
            "The canonical pre-action observation comes from the monitor-only replay, not a simultaneous replay",
            "Each action counterfactual is a separate physical trial under matched setup, not a randomized field intervention",
            "Regret uses hindsight oracle labels for scoring only, never for selection",
            "Unit repeated trials are correlated; per-configuration inference requires a preregistered study",
            "Unknown authority outcomes cannot be treated as verified cost labels",
            "Any abstention or forbidden suggestion is measured as a monitor-only fallback, not zero cost",
        ],
    }


def main():
    from model_adapter import load_local_bundle
    from train import load_executed_dataset

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--records", type=Path, required=True,
                   help="Actual complete four-stream 1200-trial evidence directory")
    p.add_argument("--model", type=Path, required=True, help="Locally trusted model file")
    p.add_argument("--trusted-model-sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error("Refusing to overwrite an existing historical experiment")
    rows = load_executed_dataset(args.records)
    dataset_digest = hashlib.sha256(json.dumps(rows, sort_keys=True,
                              separators=(",", ":")).encode()).hexdigest()
    bundle = load_local_bundle(args.model, trusted_sha256=args.trusted_model_sha256)
    report = evaluate_paired(rows, make_trusted_lab_model_policy(bundle),
                             model_fingerprint=args.trusted_model_sha256,
                             dataset_fingerprint=dataset_digest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("Saved EXPLORATORY historical comparison, no production action:", args.output)


if __name__ == "__main__":
    main()
