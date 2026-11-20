"""Strict post-hoc audit of one already-frozen historical detector report.

This NEVER trains or selects models, recalibrates cutoffs, scans networks,
or claims operational effectiveness. The test set has already been viewed.
"""
import argparse
import hashlib
import json
from pathlib import Path


SCHEMA = "predict-shield/historical-external-nsl-kdd-anomaly-evaluation/1"
OUT_SCHEMA = "predict-shield/historical-attack-family-error-audit/1"


def _nonnegative_int(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")
    return value


def audit(report):
    if not isinstance(report, dict):
        raise ValueError("Report must be an object")
    # Exact schema comes from run_historical_benchmark.py, not a generic score CSV.
    if report.get("schema") != SCHEMA:
        raise ValueError("Unexpected benchmark report schema")
    expected = {"TP": 8580, "FP": 274, "FN": 4253, "TN": 9437,
                "test_rows": 22544}
    for key, frozen in expected.items():
        if _nonnegative_int(report.get(key), key) != frozen:
            raise ValueError(f"{key} differs from the independently recorded benchmark")
    tp, fp, fn, tn = (report[k] for k in ("TP", "FP", "FN", "TN"))
    if tp + fp + fn + tn != report["test_rows"]:
        raise ValueError("Confusion-matrix denominator mismatch")
    if report.get("fit_normal_only") is not True:
        raise ValueError("Not the reported normal-only detector")
    if report.get("operational_attack_detection_established") is not False:
        raise ValueError("Operational-effectiveness claim must remain false")
    if report.get("zero_day_detection_established") is not False:
        raise ValueError("Zero-day claim must remain false")
    families = report.get("per_attack_type")
    if not isinstance(families, dict) or not families:
        raise ValueError("Missing per-family evidence")
    failures = []
    family_tested = family_detected = 0
    for name, counts in families.items():
        if not isinstance(name, str) or not name or not isinstance(counts, dict):
            raise ValueError("Invalid family row")
        tested = _nonnegative_int(counts.get("tested"), f"{name}.tested")
        detected = _nonnegative_int(counts.get("detected"), f"{name}.detected")
        if not tested or detected > tested:
            raise ValueError(f"Impossible counts for {name}")
        family_tested += tested
        family_detected += detected
        missed = tested - detected
        failures.append({"attack_type": name, "tested": tested,
                         "detected": detected, "missed": missed,
                         "recall": detected / tested,
                         "share_of_all_missed_attacks": missed / fn})
    if family_tested != tp + fn or family_detected != tp:
        raise ValueError("Family totals disagree with attack confusion matrix")
    failures.sort(key=lambda item: (-item["missed"], item["attack_type"]))
    missing = [item for item in failures if item["detected"] == 0]
    novel = {name for name in report.get("unseen_attack_type_names", [])}
    if not all(isinstance(name, str) and name in families for name in novel):
        raise ValueError("Unseen attack-type roster invalid")
    n_tp = _nonnegative_int(report.get("unseen_attack_type_TP"), "unseen TP")
    n_fn = _nonnegative_int(report.get("unseen_attack_type_FN"), "unseen FN")
    n_total = _nonnegative_int(report.get("unseen_attack_type_rows"), "unseen rows")
    if n_tp + n_fn != n_total:
        raise ValueError("Unseen attack totals inconsistent")
    if sum(families[name]["tested"] for name in novel) != n_total:
        raise ValueError("Unseen family denominators inconsistent")
    if sum(families[name]["detected"] for name in novel) != n_tp:
        raise ValueError("Unseen family detections inconsistent")
    return {
        "schema": OUT_SCHEMA,
        "source_report_sha256": hashlib.sha256(
            json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "post_hoc_only": True,
        "new_holdout": False,
        "model_retrained": False,
        "threshold_changed": False,
        "attack_rows": tp + fn, "attacks_missed": fn,
        "missed_fraction": fn / (tp + fn),
        "benign_rows": fp + tn, "benign_false_alarms": fp,
        "false_alarm_fraction": fp / (fp + tn),
        "families_ranked_by_missed_count": failures,
        "zero_recall_families": missing,
        "unseen_label_attack_rows": n_total,
        "unseen_label_detected": n_tp,
        "unseen_label_missed": n_fn,
        "limits": [
            "Already-scored historical test rows; no fresh held-out evaluation",
            "Attack-type names absent from training labels are not real zero-days",
            "No per-record anomaly scores in this report; cannot explain individual misses",
            "Row-wise historical measurements do not estimate operator incident alert rates",
            "Does not select a new threshold, feature set, or improved detector"
        ]
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = args.input.read_bytes()
    if len(source) > 2_000_000:
        raise ValueError("Report too large")
    result = audit(json.loads(source))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
