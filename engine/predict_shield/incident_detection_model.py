"""Constrained supervised attack-classification baseline for reviewed incidents.

The training records come from incident_feedback.validated_feedback, which
performs structural (NOT real-world authenticity) checks. All model fitting is
restricted to training groups. The threshold is fixed a priori at 0.5 and is
never optimized on calibration or test. Predictions and evaluation cannot
authorize a defensive action. Experimental models are NOT field validated.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections import Counter

from .incident_feedback import FEATURES, validated_feedback, score_detection


def _feature_vector(features: dict) -> list[float]:
    """Fixed, documented transformations; no learned scaling on test data."""
    return [
        float(features[name]) if name in FEATURES[:4] else math.log1p(float(features[name]))
        for name in FEATURES
    ]


def predict_probability(bundle: dict, features: dict) -> float:
    if bundle.get("schema") != "predict-shield/incident-detection-logistic/1":
        raise ValueError("unknown model schema")
    if bundle.get("feature_names") != list(FEATURES):
        raise ValueError("feature order mismatch")
    if not isinstance(features, dict) or set(features) != set(FEATURES):
        raise ValueError("exact registered pre-action feature set required")
    for name in FEATURES[:4]:
        if type(features[name]) not in (int, bool) or features[name] not in (0, 1):
            raise ValueError("invalid binary feature")
    for name in FEATURES[4:]:
        if type(features[name]) is not int or not 0 <= features[name] <= 100000:
            raise ValueError("invalid count feature")
    weights = bundle.get("coefficients")
    intercept = bundle.get("intercept")
    if not isinstance(weights, list) or len(weights) != len(FEATURES):
        raise ValueError("model coefficient count mismatch")
    if any(type(v) not in (int, float) or not math.isfinite(v) for v in weights + [intercept]):
        raise ValueError("model contains non-finite parameters")
    logit = float(intercept) + sum(float(a) * v for a, v in zip(weights, _feature_vector(features)))
    return 1 / (1 + math.exp(-max(-700, min(700, logit))))


def train_and_evaluate(incidents: list[dict]) -> tuple[dict, dict]:
    """Fit one fixed logistic baseline and evaluate once on unseen asset groups.

    Calibration rows are retained for later proper calibration analysis, but
    deliberately not used to tune this first-model threshold or fit weights.
    """
    prepared = validated_feedback(incidents)
    rows = prepared["rows"]
    by_split = {s: [r for r in rows if r["split"] == s] for s in ("train", "calibration", "test")}
    if any(not by_split[s] for s in by_split):
        raise ValueError("train, calibration, and held-out test groups required")
    train = by_split["train"]
    if len({r["asset_group"] for r in train}) < 2:
        raise ValueError("at least two separate training asset groups required")
    labels = [r["label_attack"] for r in train]
    if set(labels) != {0, 1} or min(Counter(labels).values()) < 2:
        raise ValueError("at least two independently reviewed training cases per class required")

    from sklearn.linear_model import LogisticRegression

    model = LogisticRegression(random_state=20261118, solver="liblinear", max_iter=1000)
    model.fit([_feature_vector(r["features"]) for r in train], labels)
    bundle = {
        "schema": "predict-shield/incident-detection-logistic/1",
        "feature_names": list(FEATURES),
        "coefficients": [float(x) for x in model.coef_[0]],
        "intercept": float(model.intercept_[0]),
        "threshold": 0.5,
        "training_ids_sha256": hashlib.sha256(
            json.dumps(sorted(r["incident_id"] for r in train)).encode("utf-8")
        ).hexdigest(),
        "training_data_sha256": hashlib.sha256(
            json.dumps(train, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "provenance_authentication": "NOT_ESTABLISHED",
        "calibration_supported": False,
        "decision_authorized": False,
        "production_deployable": False,
    }
    predictions = []
    for row in by_split["test"]:
        probability = predict_probability(bundle, row["features"])
        predictions.append({
            "incident_id": row["incident_id"],
            "probability": probability,
            "predict_attack": probability >= bundle["threshold"],
        })
    metrics = score_detection(
        [{"incident_id": x["incident_id"], "predict_attack": x["predict_attack"]}
         for x in predictions], prepared)
    report = {
        "schema": "predict-shield/incident-detection-evaluation/1",
        "dataset_sha256": prepared["sha256"],
        "training_groups": len({r["asset_group"] for r in train}),
        "calibration_groups_unused": len({r["asset_group"] for r in by_split["calibration"]}),
        "held_out_groups": len({r["asset_group"] for r in by_split["test"]}),
        "excluded_unknown": prepared["excluded_unknown"],
        "threshold_frozen_before_test": 0.5,
        "metrics": metrics,
        "held_out_predictions": predictions,
        "field_accuracy_established": False,
        "ai_model_trained": True,
        "model_calibrated": False,
        "interpretation": "Supervised baseline with reviewer-supplied labels; neither reviewer identities nor label truth are independently authenticated by the code.",
    }
    return bundle, report
