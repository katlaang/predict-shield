"""Train and evaluate PREDICT-SHIELD's first AI action-outcome predictor.

This script reads *executed* laboratory records only. It refuses to train on
manifest rows, partial collections, duplicated IDs or incorrect partitions.
Features are pre-action configuration and independent external deny probes.
Labels come ONLY from separately protected lab oracle + measured HTTP health
outcomes. Nothing from post-action verification, oracle truth, or post-action
telemetry becomes a model feature.

Method:
  - 60 configuration groups for model training
  - 20 configuration groups for split-conformal calibration
  - 20 configuration groups for held-out evaluation
  - paired comparison against train-only action / fault-family mean baselines

The regression models predict:
  - residual exposed target fraction (oracle-labeled)
  - failure fraction during a 40-request measured legitimate-traffic window

Split-conformal intervals here have nominal marginal coverage only under
appropriate exchangeability assumptions; no per-service safety guarantee
or production authorization is inferred. These are controlled SIMULATOR labels,
not measurements from critical-infrastructure operations.

Dependencies: numpy, scikit-learn. The training command does not run Java,
change security policies, or load an untrusted serialized model.

Usage:
  python train_action_model.py --data results --out reports/model-evaluation.json
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error

from generate_manifest import ACTIONS, CONFIGURATIONS, REPEATS, SPLITS

CATEGORICAL = ("fault_family", "action_id")
NUMERIC = (
    "enforcement_points", "stale_points", "cache_ttl_ms",
    "propagation_delay_ms", "traffic_rps", "dependency_depth", "redundancy",
)
FAULT_TYPES = (
    "stale_cache", "lost_event", "delayed_event",
    "duplicate_event", "silent_rebuild", "reordered_event",
)
FEATURE_NAMES = NUMERIC + ("initial_allowed_fraction",) + tuple(
    "fault=" + f for f in FAULT_TYPES
) + tuple("action=" + a for a in ACTIONS)


def record_map(folder: Path) -> dict[str, dict]:
    """Load a complete record directory, rejecting missing and duplicate IDs."""
    if not folder.is_dir():
        raise ValueError("Missing executed record directory: " + str(folder))
    records = {}
    for file in folder.glob("*.json"):
        item = json.loads(file.read_text(encoding="utf-8"))
        run_id = item.get("run_id")
        if not isinstance(run_id, str) or not run_id or run_id in records:
            raise ValueError("Invalid or duplicate run ID in " + str(folder))
        records[run_id] = item
    return records


def checked_records(directory: Path) -> list[dict]:
    """Join the separated training records strictly by run ID and split group.

    This function does not allow evaluation-time oracle attributes to be
    materialized as pre-action features; the returned dictionary has a
    dedicated private label section rather than merging record properties.
    """
    pre = record_map(directory / "pre_action")
    verification = record_map(directory / "verification")
    operations = record_map(directory / "operations")
    oracle = record_map(directory / "oracle")
    expected_count = CONFIGURATIONS * len(ACTIONS) * REPEATS
    if any(len(x) != expected_count for x in (pre, verification, operations, oracle)):
        raise ValueError("Refusing incomplete 100 x 4 x 3 execution records")
    if not (pre.keys() == verification.keys() == operations.keys() == oracle.keys()):
        raise ValueError("Unmatched run IDs across separated record streams")
    examples = []
    split_by_config = {}
    for run_id, before in pre.items():
        operation = operations[run_id]
        truth = oracle[run_id]
        verify = verification[run_id]
        config = before["features"]
        group = before["configuration_id"]
        split = before["split"]
        if not all(x["configuration_id"] == group and x["split"] == split
                   and x["action_id"] == before["action_id"]
                   for x in (operation, truth, verify)):
            raise ValueError("Cross-record run metadata mismatch")
        if group in split_by_config and split_by_config[group] != split:
            raise ValueError("Split leakage across repeats or action replays")
        split_by_config[group] = split
        if truth.get("oracle_kind") != "internal_java_fixture_separately_credentialed_same_process":
            raise ValueError("Unrecognized oracle provenance")
        statuses = before["external_deny_observations"]
        if len(statuses) != int(config["enforcement_points"]):
            raise ValueError("Pre-action scope mismatch")
        if any(item.get("http_status") not in (200, 403) for item in statuses):
            raise ValueError("Unresolved pre-action probe; exclude and rerun")
        allowed = sum(item["http_status"] == 200 for item in statuses)
        allowed_states = truth.get("actual_authorization_allowed")
        health = operation["service_health"]
        if not isinstance(allowed_states, list) or len(allowed_states) != config["enforcement_points"]:
            raise ValueError("Missing or incomplete independent lab oracle scope")
        if any(type(value) is not bool for value in allowed_states):
            raise ValueError("Oracle authorization states must be Boolean")
        attempted = health.get("requests_attempted")
        failed = health.get("failed_or_non_200_requests")
        if attempted != 40 or not isinstance(failed, int) or not 0 <= failed <= attempted:
            raise ValueError("Missing or invalid measured legitimate traffic")
        if not health.get("measurement_complete", False):
            raise ValueError("Incomplete service-health observation")
        if before.get("model_prediction_recorded") is not False:
            raise ValueError("Expected pre-action baseline without post-action model predictions")
        examples.append({
            "run_id": run_id, "group": group, "split": split,
            "action_id": before["action_id"],
            "fault_family": config["fault_family"],
            "config": config,
            "initial_allowed_fraction": allowed / len(statuses),
            "label_residual_exposure": sum(allowed_states) / len(allowed_states),
            "label_service_failure": failed / attempted,
        })
    if len(split_by_config) != CONFIGURATIONS:
        raise ValueError("Expected 100 unique configuration groups")
    if Counter(split_by_config.values()) != SPLITS:
        raise ValueError("Unexpected configuration-level train/calibration/test split")
    return sorted(examples, key=lambda row: row["run_id"])


def feature_vector(example: dict) -> list[float]:
    """Encode only registered pre-action features with fixed category columns."""
    cfg = example["config"]
    return [float(cfg[name]) for name in NUMERIC] + [
        float(example["initial_allowed_fraction"])
    ] + [float(example["fault_family"] == fault) for fault in FAULT_TYPES] + [
        float(example["action_id"] == action) for action in ACTIONS
    ]


def conformal_radius(y_cal: np.ndarray, predictions_cal: np.ndarray,
                     alpha: float = 0.10) -> float:
    """Return split-conformal absolute-error radius at nominal 1-alpha level.

    The finite-sample quantile uses ceil((n+1)*(1-alpha))/n and higher
    interpolation. It does not provide conditional coverage for rare faults,
    and calibration results do not authorize real defensive actions.
    """
    if not 0 < alpha < 1 or len(y_cal) == 0:
        raise ValueError("Unusable conformal calibration partition")
    residuals = np.sort(np.abs(y_cal - predictions_cal))
    index = min(len(residuals) - 1, math.ceil((len(residuals) + 1) * (1 - alpha)) - 1)
    return float(residuals[index])


def action_fault_means(train: list[dict], label: str) -> dict[tuple[str, str], float]:
    """Compute a deliberately competitive action-and-fault lookup baseline."""
    sums: dict[tuple[str, str], list[float]] = {}
    for example in train:
        key = (example["action_id"], example["fault_family"])
        sums.setdefault(key, []).append(float(example[label]))
    return {key: float(np.mean(values)) for key, values in sums.items()}


def train_and_report(examples: list[dict], seed: int = 20261110) -> dict:
    """Fit two supervised regressors and evaluate once on held-out groups.

    Models are frozen before test evaluation. Hyperparameters are prespecified;
    test labels are never used in fitting, feature selection or conformal
    calibration. Any later tuning must use new held-out evaluations.
    """
    by_split = {split: [row for row in examples if row["split"] == split]
                for split in SPLITS}
    if any(not rows for rows in by_split.values()):
        raise ValueError("Training, calibration and test groups are mandatory")
    train = by_split["train"]
    calibration = by_split["calibration"]
    test = by_split["test"]
    partitions = [
        {row["group"] for row in by_split[name]} for name in SPLITS
    ]
    if (partitions[0] & partitions[1] or partitions[1] & partitions[2]
            or partitions[0] & partitions[2]):
        raise ValueError("Configuration groups leak across partitions")
    matrix = {
        name: np.array([feature_vector(row) for row in rows], dtype=np.float64)
        for name, rows in by_split.items()
    }
    result = {
        "study": "PREDICT-SHIELD Experiment B controlled-fixture action prediction",
        "not_production_validation": True,
        "model_type": "RandomForestRegressor",
        "model_parameters": {"n_estimators": 200, "min_samples_leaf": 3,
                             "random_state": seed, "n_jobs": 1},
        "features": list(FEATURE_NAMES),
        "group_counts": {name: len(partition) for name, partition
                         in zip(SPLITS, partitions)},
        "trial_counts": {name: len(by_split[name]) for name in SPLITS},
        "oracle_scope": "same_process_java_lab_fixture",
        "test_partition_tuned": False,
        "targets": {},
    }
    for label in ("label_residual_exposure", "label_service_failure"):
        y = {name: np.array([row[label] for row in rows], dtype=np.float64)
             for name, rows in by_split.items()}
        model = RandomForestRegressor(
            n_estimators=200, min_samples_leaf=3, random_state=seed, n_jobs=1
        )
        model.fit(matrix["train"], y["train"])
        predicted_cal = np.clip(model.predict(matrix["calibration"]), 0, 1)
        predicted_test = np.clip(model.predict(matrix["test"]), 0, 1)
        radius = conformal_radius(y["calibration"], predicted_cal)
        lower = np.clip(predicted_test - radius, 0, 1)
        upper = np.clip(predicted_test + radius, 0, 1)
        lookup = action_fault_means(train, label)
        global_action = {
            action: float(np.mean([r[label] for r in train if r["action_id"] == action]))
            for action in ACTIONS
        }
        baseline_predictions = np.array([
            lookup.get((row["action_id"], row["fault_family"]),
                       global_action[row["action_id"]])
            for row in test
        ])
        result["targets"][label] = {
            "held_out_model_mae": float(mean_absolute_error(y["test"], predicted_test)),
            "held_out_action_fault_lookup_mae": float(mean_absolute_error(
                y["test"], baseline_predictions)),
            "held_out_interval_coverage": float(np.mean(
                (y["test"] >= lower) & (y["test"] <= upper))),
            "nominal_marginal_coverage": 0.90,
            "calibration_absolute_error_radius": radius,
            "held_out_count": len(test),
            "interpretation": "Simulator-only predictive validity, not causal or field effectiveness",
        }
    return result


def main() -> None:
    """Load a complete sealed dataset, train without oracle leakage and save metrics."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    examples = checked_records(args.data)
    report = train_and_report(examples)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print("Evaluated model on held-out experiment configurations; report:", args.out)


if __name__ == "__main__":
    main()
