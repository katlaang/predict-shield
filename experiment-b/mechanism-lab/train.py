"""Train and evaluate action-effectiveness predictions on executed mechanism trials.

Only real measured records from the distinct Kafka/JVM experiment are allowed.
Pre-action features are constructed exclusively from the pre_action stream.
Labels come from the separately collected oracle and operations streams.
Verification outcomes are inspected for matching metadata but never supplied
as model features. Configurations, not individual repeated trials, are split
60/20/20 for train, calibration and held-out test.

A fitted random forest is compared to train-only action means and train-only
action-by-fault and action-by-fault-by-target lookup baselines. The 90% nominal
split-conformal radius is evaluated on the held-out test partition, and does
not justify safety-critical automatic execution under distribution shift.

This experiment intentionally produces an evaluation report only, not an
implicitly deployable model. Serving a calibrated model is a separate
authorization and artifact-provenance milestone.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from collections import Counter
from pathlib import Path

FAULTS = ("loss", "delay", "duplicate", "reorder")
TARGETS = ("enforcer-a", "enforcer-b", "enforcer-c")
ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")
SPLITS = {"train": 60, "calibration": 20, "test": 20}
EXPECTED_TRIALS = 1200

# The trained model must not see laboratory-injected fault labels or timing.
# Those variables remain available only for post-hoc stratification and an
# explicitly *privileged* diagnostic lookup baseline.
FEATURES = (
    "cache_ttl_ms", "requested_rps",
    "initial_gateway_allowed_fraction",
) + tuple("action=" + x for x in ACTIONS)


def _read_stream(path: Path) -> dict[str, dict]:
    """Read a complete on-disk record directory with strict unique run IDs."""
    if not path.is_dir():
        raise ValueError("Missing measured data stream: " + str(path))
    result = {}
    for file in path.glob("*.json"):
        value = json.loads(file.read_text(encoding="utf-8"))
        run_id = value.get("run_id")
        if not isinstance(run_id, str) or not run_id or run_id in result:
            raise ValueError("Duplicate or invalid executed run ID")
        result[run_id] = value
    return result


def load_executed_dataset(path: Path) -> list[dict]:
    """Require complete 1,200-trial measurements with partition provenance.

    The manifest alone is insufficient: no missing oracle, failed operation,
    overwritten record, duplicated configuration, or incorrectly joined
    record can silently become a label. The common code path intentionally
    excludes all oracle fields from returned pre-action features.
    """
    streams = {name: _read_stream(path / name) for name in
               ("pre_action", "verification", "operations", "oracle")}
    if any(len(stream) != EXPECTED_TRIALS for stream in streams.values()):
        raise ValueError("Refusing training: incomplete 1,200-trial measured dataset")
    ids = set(streams["pre_action"])
    if any(set(s) != ids for s in streams.values()):
        raise ValueError("Four record streams have mismatched run IDs")
    examples = []
    partition_by_config: dict[str, str] = {}
    action_groups: dict[tuple[str, int], set[str]] = {}
    paired_static_features: dict[tuple[str, int], tuple] = {}
    for run_id in sorted(ids):
        a, v, o, oracle = (streams[key][run_id] for key in
                           ("pre_action", "verification", "operations", "oracle"))
        for other in (v, o, oracle):
            if (other["run_id"] != run_id or
                    other["configuration_id"] != a["configuration_id"] or
                    other["partition"] != a["partition"] or
                    other["action_id"] != a["action_id"]):
                raise ValueError("Cross-stream record identity mismatch")
        if (a["experiment_type"] != "real_kafka_multijvm_lab"
                or a.get("model_prediction_recorded") is not False
                or a.get("oracle_features_excluded") is not True):
            raise ValueError("Dataset is not a pre-action mechanism experiment")
        conf, partition = a["configuration_id"], a["partition"]
        if conf in partition_by_config and partition_by_config[conf] != partition:
            raise ValueError("Train/calibration/test group leakage")
        partition_by_config[conf] = partition
        group_key = (conf, a["repeat"])
        action_groups.setdefault(group_key, set()).add(a["action_id"])
        features = a["features"]
        conditions = a.get("experimental_conditions", {})
        if any(key in features for key in ("fault_mode", "fault_target", "event_delay_ms")):
            raise ValueError("Injected hidden fault metadata leaked into model features")
        static_key = (
            a.get("initial_state_seed"),
            conditions.get("fault_mode"),
            conditions.get("fault_target"),
            features.get("cache_ttl_ms"),
            conditions.get("event_delay_ms"),
            features.get("requested_rps"),
            features.get("measurement_seconds"),
        )
        if group_key in paired_static_features and paired_static_features[group_key] != static_key:
            raise ValueError("Matched actions do not share the registered starting conditions")
        paired_static_features[group_key] = static_key
        if (conditions.get("fault_mode") not in FAULTS
                or conditions.get("fault_target") not in TARGETS
                or a["action_id"] not in ACTIONS):
            raise ValueError("Unregistered fault, target or action")
        observations = a["external_deny_observations"]
        if not observations or any(x.get("http_status") not in (200, 403)
                                   for x in observations):
            raise ValueError("Incomplete pre-action observation")
        if (not oracle["after"].get("inventory_complete")
                or oracle["after"].get("all_revoked_access_denied") is None
                or not isinstance(oracle["after"].get("targets"), list)):
            raise ValueError("Missing independent oracle truth")
        if oracle["oracle_role"] != "separate_process_admin_plus_direct_probe":
            raise ValueError("Oracle provenance unrecognized")
        attempted = o.get("observed_requests")
        failures = o.get("failed_requests")
        if (not isinstance(attempted, int) or attempted < 1 or
                not isinstance(failures, int) or not 0 <= failures <= attempted):
            raise ValueError("Missing actual service-health measurements")
        # Target labels are isolated until this post-hoc training/evaluation phase.
        examples.append({
            "group": conf, "partition": partition,
            "action": a["action_id"], "fault": conditions["fault_mode"],
            "target": conditions["fault_target"],
            "pre_action": {
                "cache_ttl_ms": features["cache_ttl_ms"],
                "requested_rps": features["requested_rps"],
                "initial_gateway_allowed_fraction": sum(
                    x["http_status"] == 200 for x in observations) / len(observations),
            },
            "label_security_exposure": float(
                not oracle["after"]["all_revoked_access_denied"]),
            "label_service_failure_fraction": failures / attempted,
        })
    if Counter(partition_by_config.values()) != SPLITS:
        raise ValueError("Expected exactly 60/20/20 distinct configuration groups")
    if len(action_groups) != 300 or any(actions != set(ACTIONS)
                                        for actions in action_groups.values()):
        raise ValueError("Action or repeat pairings are incomplete")
    return examples


def to_features(row: dict) -> list[float]:
    """Encode only operator-observable pre-action inputs and action identity.

    Injected fault labels and timing remain deliberately excluded to avoid
    turning a hidden experimental intervention into a model shortcut.
    """
    p = row["pre_action"]
    return [float(p[k]) for k in (
        "cache_ttl_ms", "requested_rps", "initial_gateway_allowed_fraction",
    )] + [float(row["action"] == x) for x in ACTIONS]


def conformal_radius(actual, predicted, alpha: float = 0.1) -> float:
    """Calculate a conservative split-conformal marginal absolute-error radius."""
    if not 0 < alpha < 1 or len(actual) < 1 or len(actual) != len(predicted):
        raise ValueError("Invalid calibration data")
    residuals = sorted(abs(float(a) - float(p)) for a, p in zip(actual, predicted))
    return residuals[min(len(residuals) - 1,
                         math.ceil((len(residuals) + 1) * (1 - alpha)) - 1)]


def train_evaluate(rows: list[dict], seed: int = 20261110,
                   *, export_path: Path | None = None) -> dict:
    """Fit models on training groups and compare once on held-out groups.

    Uses an operational action-only lookup baseline and an explicitly privileged
    diagnostic fault/target lookup that is not considered a fair operational competitor. No test-set results are used to select features,
    hyperparameters, interval radii, or baselines.
    """
    groups = {name: [r for r in rows if r["partition"] == name]
              for name in SPLITS}
    sets = [{r["group"] for r in group} for group in groups.values()]
    if any(not group for group in groups.values()) or any(
        sets[i] & sets[j] for i in range(3) for j in range(i + 1, 3)
    ):
        raise ValueError("No valid disjoint train/calibration/test groups")

    # Validate experiment group isolation before importing optional ML packages.
    import numpy as np
    from sklearn.ensemble import RandomForestRegressor
    from sklearn.metrics import mean_absolute_error

    fitted_models = {}
    calibration_radii = {}
    report = {
        "schema": "predict-shield/mechanism-model-evaluation/1",
        "not_production_effectiveness": True,
        "model": "RandomForestRegressor",
        "feature_names": list(FEATURES),
        "configuration_group_counts": {k: len({r["group"] for r in v})
                                       for k, v in groups.items()},
        "trial_counts": {k: len(v) for k, v in groups.items()},
        "metrics": {},
        "model_automatically_dispatched": False,
        "fault_injection_metadata_used_as_model_features": False,
        "test_used_for_training_or_calibration": False,
    }
    matrices = {k: np.asarray([to_features(r) for r in v], dtype=float)
                for k, v in groups.items()}
    for label in ("label_security_exposure", "label_service_failure_fraction"):
        train, cal, test = (groups[k] for k in SPLITS)
        y = {k: np.asarray([r[label] for r in v], dtype=float)
             for k, v in groups.items()}
        model = RandomForestRegressor(n_estimators=200, min_samples_leaf=3,
                                      random_state=seed, n_jobs=1)
        model.fit(matrices["train"], y["train"])
        fitted_models[label] = model
        pred_cal = np.clip(model.predict(matrices["calibration"]), 0, 1)
        pred_test = np.clip(model.predict(matrices["test"]), 0, 1)
        radius = conformal_radius(y["calibration"], pred_cal)
        calibration_radii[label] = radius
        low = np.clip(pred_test - radius, 0, 1)
        high = np.clip(pred_test + radius, 0, 1)
        lookup = {}
        for r in train:
            for key in (
                (r["action"], r["fault"], r["target"]),
                (r["action"], r["fault"]),
                (r["action"],),
            ):
                lookup.setdefault(key, []).append(r[label])
        averages = {k: float(np.mean(v)) for k, v in lookup.items()}
        def baseline(r):
            for key in (
                (r["action"], r["fault"], r["target"]),
                (r["action"], r["fault"]),
                (r["action"],),
            ):
                if key in averages:
                    return averages[key]
            raise ValueError("Action not seen in training")
        baseline_test = np.asarray([baseline(r) for r in test])
        # Comparable deployment baseline: action averages only, without the
        # laboratory's hidden fault label or injected target identity.
        action_means = {action: float(np.mean([
            item[label] for item in train if item["action"] == action]))
            for action in ACTIONS}
        action_baseline = np.asarray([action_means[item["action"]] for item in test])
        report["metrics"][label] = {
            "action_only_lookup_heldout_mae": float(mean_absolute_error(
                y["test"], action_baseline)),
            "privileged_fault_lookup_is_not_operational_baseline": True,
            "model_heldout_mae": float(mean_absolute_error(y["test"], pred_test)),
            "privileged_fault_lookup_heldout_mae": float(mean_absolute_error(
                y["test"], baseline_test)),
            "marginal_interval_coverage": float(np.mean(
                (y["test"] >= low) & (y["test"] <= high))),
            "conformal_absolute_error_radius": radius,
            "nominal_coverage": 0.90,
            "heldout_test_count": len(test),
            "caveat": "Only measured laboratory behavior; not conditional service safety",
        }
    if export_path is not None:
        # Only load model artifacts created in a trusted local environment.
        # The scikit-learn serialization is pickle-based and unsafe to load
        # from arbitrary external sources.
        import joblib
        export_path.parent.mkdir(parents=True, exist_ok=True)
        if export_path.exists():
            raise FileExistsError("Refusing to overwrite existing model artifact")
        training_rows = [
            {
                "group": r["group"], "action": r["action"],
                "fault": r["fault"], "target": r["target"],
                "pre_action": r["pre_action"],
                "label_security_exposure": r["label_security_exposure"],
                "label_service_failure_fraction": r["label_service_failure_fraction"],
            }
            for r in groups["train"]
        ]
        training_rows.sort(key=lambda item: json.dumps(item, sort_keys=True))
        # Fingerprint the measured training values, not merely run IDs.
        fingerprint = hashlib.sha256(
            json.dumps(training_rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        bundle = {
            "schema": "predict-shield/mechanism-model-bundle/1",
            "model_type": "RandomForestRegressor",
            "features": list(FEATURES),
            "training_fingerprint": fingerprint,
            "training_group_count": len(sets[0]),
            "calibration_group_count": len(sets[1]),
            "numeric_feature_bounds": {
                name: [float(matrices["train"][:, i].min()),
                       float(matrices["train"][:, i].max())]
                for i, name in enumerate(FEATURES)
                if i < 4
            },
            "radii": calibration_radii,
            "models": fitted_models,
            "trust_boundary": "trusted local training artifact; never load externally supplied pickle",
            "not_certified_for_automatic_execution": True,
        }
        fd = os.open(export_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as destination:
            joblib.dump(bundle, destination)
        report["exported_model_path"] = str(export_path)
        report["training_fingerprint"] = fingerprint
    return report


def main() -> None:
    """Refuse manifest-only input and write an explicitly labeled evaluation report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--export-model", type=Path,
                        help="Optional local-only trusted pickle bundle for later inference")
    args = parser.parse_args()
    rows = load_executed_dataset(args.records)
    result = train_evaluate(rows, export_path=args.export_model)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as file:
        json.dump(result, file, indent=2, sort_keys=True)
        file.write("\n")
    print("Saved held-out *laboratory* evaluation report:", args.report)


if __name__ == "__main__":
    main()
