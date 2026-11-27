"""Frozen operating-point evaluator for research cohorts.

Threshold selection is confined to the independently reviewed benign
calibration partition. No final-test score or label contributes to its
selection. Accepts validated manifests from cohort_guard.py only.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

from cohort_guard import audit


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def frozen_threshold(calibration_scores, alert_budget=0.005):
    if not _number(alert_budget) or not 0 < alert_budget < 1:
        raise ValueError("alert budget must lie strictly between zero and one")
    if len(calibration_scores) < 1000:
        raise ValueError("at least 1000 independently reviewed benign calibration scores required")
    if any(not _number(x) for x in calibration_scores):
        raise ValueError("scores must be finite real numbers")
    ordered = sorted(calibration_scores)
    # Strict > threshold, at most floor(n * budget) alerts on calibration.
    allowed = math.floor(len(ordered) * alert_budget)
    threshold = ordered[len(ordered) - allowed - 1]
    observed = sum(x > threshold for x in ordered) / len(ordered)
    assert observed <= alert_budget
    return {"threshold": threshold, "calibration_benign": len(ordered),
            "calibration_alerts": sum(x > threshold for x in ordered),
            "calibration_alert_rate": observed, "alert_budget": alert_budget,
            "scope": "calibration only"}


def evaluate(manifest, dataset_root: Path, *, model_sha256: str, alert_budget=0.005):
    import re
    if not isinstance(model_sha256, str) or re.fullmatch(r"[a-f0-9]{64}", model_sha256) is None:
        raise ValueError("model SHA-256 missing")
    admission = audit(manifest, dataset_root=dataset_root)
    if admission["status"] != "READY_FOR_EVALUATION":
        raise ValueError("cohort admission failed: " + admission["status"] + " " +
                         "; ".join(admission["errors"] + admission["blockers"]))
    rows = manifest["rows"]
    cal = [r["score"] for r in rows
           if r["role"] == "calibration" and r["label"] == "benign" and
           r["truth_basis"] == "independently_reviewed_event"]
    criterion = frozen_threshold(cal, alert_budget)
    thresh = criterion["threshold"]
    eligible = [r for r in rows if r["role"] == "test" and
                r["truth_basis"] == "independently_reviewed_event" and
                r["label"] in ("attack", "benign")]
    if any("score" not in r or not _number(r["score"]) for r in eligible):
        raise ValueError("test scores missing/non-finite")
    benign = [r for r in eligible if r["label"] == "benign"]
    attack = [r for r in eligible if r["label"] == "attack"]
    false_alarms = sum(r["score"] > thresh for r in benign)
    detected = sum(r["score"] > thresh for r in attack)
    by_capture = {}
    for r in eligible:
        group = r["source_id"] + "::" + r["capture_group"]
        ent = by_capture.setdefault(group, {"benign": 0, "attack": 0,
                                             "benign_alerts": 0, "attack_alerts": 0})
        ent[r["label"]] += 1
        ent["benign_alerts" if r["label"] == "benign" else "attack_alerts"] += int(r["score"] > thresh)
    unknown = sum(r["role"] == "test" and
                  (r["truth_basis"] != "independently_reviewed_event" or r["label"] == "unknown")
                  for r in rows)
    return {
        "schema": "predict-shield/frozen-detector-evaluation/1",
        "model_sha256": model_sha256,
        "protocol_sha256": manifest["protocol_sha256"],
        "calibration": criterion,
        "test": {
            "benign": len(benign), "false_alerts": false_alarms,
            "observed_fpr": false_alarms / len(benign),
            "attacks": len(attack), "detected": detected,
            "observed_recall": detected / len(attack),
            "unknown_or_scenario_labeled_excluded": unknown,
            "by_capture_group": dict(sorted(by_capture.items())),
        },
        "limits": [
            "No threshold was selected from final test scores or labels",
            "Event-level rates do not imply independent observations or field performance",
            "Capture-group dependence requires grouped uncertainty intervals before superiority claims",
            "No confusion matrix is inferred for unknown or scenario-only labels",
        ],
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("manifest", type=Path)
    p.add_argument("--data-root", type=Path, required=True)
    p.add_argument("--model-sha256", required=True)
    p.add_argument("--alert-budget", type=float, default=0.005)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error("refusing to overwrite an existing evaluation")
    report = evaluate(json.loads(args.manifest.read_text()), args.data_root,
                      model_sha256=args.model_sha256, alert_budget=args.alert_budget)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("Evaluation written; no scientific superiority claim implied")


if __name__ == "__main__":
    main()
