"""Learned, signature-free flow anomaly detection research path.

Isolation Forest fits ONLY reviewed normal training flows; it does not
consume known attacks or any explicit ATT&CK/signature rules while fitting.
A calibration-only false-alert ceiling selects the anomaly cutoff before
test data is loaded. Unknown publisher labels are never relabeled benign.
Anomalies are suspicious *candidates*, not adjudicated attacks.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path

from fit_evaluate import (_validate_manifest, _read_one, SPLITS, NUMERIC,
                          PROTOCOLS, feature, classify_label, FIELDS)

SCHEMA = "predict-shield/ctu13-unsupervised-isolation-forest/1"
SEED = 20261119


def _cutoff(normal_scores: list[float], max_fpr: float) -> float:
    """Choose one cutoff using benign calibration scores only.

    Alert when anomaly_score > cutoff. The cutoff equals the k-th largest
    observed score where k=floor(max_fpr * n). Ties remain benign.
    Thus the calibration FPR cannot exceed the registered ceiling.
    """
    if not normal_scores:
        raise ValueError("calibration normal examples required")
    if type(max_fpr) not in (int, float) or isinstance(max_fpr, bool) or (
            not math.isfinite(max_fpr) or not 0 <= max_fpr <= .25):
        raise ValueError("invalid calibration false-positive ceiling")
    n = len(normal_scores)
    k = math.floor(max_fpr * n)
    if k == 0:
        return max(normal_scores)
    return sorted(normal_scores, reverse=True)[k - 1]


def _score(model, vectors: list[list[float]]) -> list[float]:
    if not vectors:
        return []
    # Higher negative score_samples = more anomalous. No matching rules.
    values = (-model.score_samples(vectors)).tolist()
    if not all(math.isfinite(x) for x in values):
        raise ValueError("nonfinite learned model scores")
    return values


def fit_and_evaluate(manifest: dict, manifest_bytes: bytes, root: Path):
    """Return a trained sklearn model, a frozen configuration, and evaluation.

    Model is deliberately retained only in memory; no unsafe pickle files
    or automatically deployable production artifact is emitted.
    """
    sources = _validate_manifest(manifest, root)
    # Load train/calibration before test to enforce model/threshold freeze.
    rows = {split: [] for split in SPLITS}
    records = []
    for split in SPLITS:
        for entry in sources:
            if entry["split"] != split:
                continue
            samples, stats = _read_one(
                entry, root, manifest["sample_cap_per_label_per_scenario"])
            rows[split].extend(samples)
            records.append(stats)
    for split in SPLITS:
        labels = {label for _, label in rows[split]}
        if labels != {0, 1}:
            raise ValueError("both known botnet and normal samples required in every split")
    normals = [vec for vec, label in rows["train"] if label == 0]
    calibration_normals = [vec for vec, label in rows["calibration"] if label == 0]
    if len(normals) < 8 or len(calibration_normals) < 4:
        raise ValueError("insufficient benign examples for unsupervised training/calibration")

    from sklearn.ensemble import IsolationForest
    # Training never uses known attack labels, rule matches, or ATT&CK IDs.
    model = IsolationForest(
        n_estimators=100, max_samples=min(256, len(normals)),
        random_state=SEED, contamination="auto", n_jobs=1)
    model.fit(normals)
    calibration_scores = _score(model, calibration_normals)
    ceiling = manifest["max_calibration_sample_false_positive_rate"]
    threshold = _cutoff(calibration_scores, ceiling)
    calibration_fp = sum(score > threshold for score in calibration_scores)
    assert calibration_fp / len(calibration_scores) <= ceiling + 1e-12

    # Only now evaluate the predeclared separate scenario test population.
    # Labels are used solely for evaluation, never model fitting/cutoff.
    scores = _score(model, [vec for vec, _ in rows["test"]])
    labels = [label for _, label in rows["test"]]
    flagged = [score > threshold for score in scores]
    counts = Counter(
        "TP" if predicted and label else
        "FP" if predicted else "FN" if label else "TN"
        for predicted, label in zip(flagged, labels))
    tp, fp, fn, tn = (counts[key] for key in ("TP", "FP", "FN", "TN"))
    def rate(a, b):
        return a / b if b else None
    bundle = {
        "schema": SCHEMA,
        "method": "unsupervised_isolation_forest_normal_only",
        "feature_names": list(NUMERIC) + ["proto=" + p for p in PROTOCOLS],
        "threshold": float(threshold),
        "threshold_comparison": "anomaly_score_strictly_greater_than_threshold",
        "calibration_selection": "benign_calibration_only_with_registered_sample_fpr_ceiling",
        "train_source_digests": [row["source_sha256"] for row in records
                                 if row["split"] == "train"],
        "model_hyperparameters": {"n_estimators": 100,
                                  "max_samples": min(256, len(normals)),
                                  "random_state": SEED,
                                  "contamination": "auto"},
        "model_serialized_for_deployment": False,
        "production_deployable": False,
        "decision_authorized": False,
        "explicit_signatures_used_for_detection": False,
    }
    report = {
        "schema": "predict-shield/ctu13-unsupervised-evaluation/1",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "model_configuration_sha256": hashlib.sha256(
            json.dumps(bundle, sort_keys=True).encode()).hexdigest(),
        "source_stats": records,
        "train_known_normal_flows": len(normals),
        "train_known_botnet_flows_used": 0,
        "calibration_known_normal_flows": len(calibration_normals),
        "calibration_false_positives": calibration_fp,
        "calibration_sample_fpr": calibration_fp / len(calibration_normals),
        "max_registered_sample_fpr": ceiling,
        "frozen_threshold": threshold,
        "test_flows": len(scores),
        "test_scenario_ids": [row["scenario_id"] for row in records
                              if row["split"] == "test"],
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "test_sample_recall": rate(tp, tp + fn),
        "test_sample_precision": rate(tp, tp + fp),
        "test_sample_false_positive_rate": rate(fp, fp + tn),
        "class_stratified_sampling": True,
        "sample_precision_is_operational_precision": False,
        "unknown_label_flows_excluded": sum(row["excluded_unknown"] for row in records),
        "anomaly_is_confirmed_attack": False,
        "production_effectiveness_established": False,
        "independently_authenticated_labels": False,
        "actual_ctu13_data_measured": True,
        "interpretation": "Suspect flow anomalies learned from publisher-labeled normal training samples; sampled held-out scenario results only. Not novel-attack confirmation.",
    }
    return model, bundle, report


def detect_unlabeled(model, bundle: dict, flows: list[dict]) -> list[dict]:
    """Run a previously fitted anomaly model on live-shaped *unlabeled* rows.

    No Label or other ground-truth field may enter this inference boundary.
    Returns only investigation candidates, never an authorization decision.
    """
    if (not isinstance(bundle, dict) or bundle.get("schema") != SCHEMA
            or bundle.get("decision_authorized") is not False):
        raise ValueError("unauthorized or incompatible detection bundle")
    threshold = bundle.get("threshold")
    if type(threshold) not in (int, float) or not math.isfinite(threshold):
        raise ValueError("invalid frozen detection threshold")
    if not isinstance(flows, list):
        raise TypeError("flows must be a list")
    for item in flows:
        if not isinstance(item, dict) or "Label" in item or "label_attack" in item:
            raise ValueError("ground-truth labels are prohibited at inference")
    scores = _score(model, [feature(row) for row in flows])
    return [{
        "flow_index": idx,
        "anomaly_score": score,
        "investigation_candidate": bool(score > threshold),
        "attack_confirmed": False,
        "defensive_action_authorized": False,
        "detection_method": "learned_unsupervised_anomaly",
    } for idx, score in enumerate(scores)]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--data-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--unlabeled-flows", type=Path,
                   help="Optional JSON array of feature-only flow rows for read-only anomaly scoring")
    args = p.parse_args()
    raw = args.manifest.read_bytes()
    model, bundle, report = fit_and_evaluate(
        json.loads(raw), raw, args.data_root)
    output = {"model_configuration": bundle, "evaluation": report}
    if args.unlabeled_flows:
        flows = json.loads(args.unlabeled_flows.read_text())
        output["read_only_anomaly_candidates"] = detect_unlabeled(model, bundle, flows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as dst:
        json.dump(output, dst, indent=2, sort_keys=True)
        dst.write("\n")
    print(json.dumps({
        "test_flows": report["test_flows"],
        "TP": report["TP"], "FP": report["FP"],
        "FN": report["FN"], "TN": report["TN"],
        "real_dataset_labels_independently_authenticated": False,
        "production_effectiveness_established": False,
    }))


if __name__ == "__main__":
    main()
