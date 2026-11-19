"""Training/test and safety controls for supervised incident detector.

All generated rows are synthetic fixtures, NOT independent attack recordings.
"""
from __future__ import annotations

import copy
import math
import unittest

from predict_shield.incident_detection_model import (
    train_and_evaluate, predict_probability,
)
from predict_shield.incident_feedback import SCHEMA


def incident(i, group, split, attack, unknown=False):
    return {
        "schema": SCHEMA,
        "incident_id": f"case-{i}",
        "asset_group": group,
        "split": split,
        "detected_at": "2026-11-18T18:00:00Z",
        "alert_evidence_sha256": f"{i:064x}",
        "signal_source_id": "signed-ids",
        "pre_action_features": {
            "network_alert": bool(attack),
            "endpoint_alert": bool(attack and i % 2),
            "known_vulnerability": bool(attack and i % 3),
            "observed_remote_access": bool(attack),
            "critical_service_count": 1 + i % 3,
            "independent_source_count": 2 if attack else 1,
        },
        "independent_review": {
            "reviewer_id": "synthetic-reviewer-fixture",
            "reviewed_at": "2026-11-18T19:00:00Z",
            "verdict": "UNKNOWN" if unknown else "ATTACK" if attack else "BENIGN",
            "independent_evidence_sha256": f"{100000 + i:064x}",
        },
    }


def fixture():
    items = []
    n = 1
    for split, groups in (("train", 4), ("calibration", 2), ("test", 3)):
        for g in range(groups):
            for attack in (False, True):
                items.append(incident(n, f"{split}-group-{g}", split, attack))
                n += 1
    items.append(incident(n, "test-group-0", "test", True, unknown=True))
    return items


class IncidentDetectorTests(unittest.TestCase):
    def test_fit_evaluate_and_freeze_without_field_claim(self):
        model, report = train_and_evaluate(fixture())
        self.assertEqual(report["schema"], "predict-shield/incident-detection-evaluation/1")
        self.assertEqual(report["metrics"]["test_cases"], 6)
        self.assertEqual(report["excluded_unknown"], 1)
        self.assertEqual(report["training_groups"], 4)
        self.assertEqual(report["held_out_groups"], 3)
        self.assertEqual(report["calibration_groups_unused"], 2)
        self.assertFalse(report["field_accuracy_established"])
        self.assertFalse(model["decision_authorized"])
        self.assertFalse(model["calibration_supported"])
        self.assertEqual(len(report["held_out_predictions"]), 6)
        self.assertTrue(all(0 <= p["probability"] <= 1 for p in report["held_out_predictions"]))
        self.assertEqual(sum(report["metrics"][k] for k in ("TP","FP","FN","TN")), 6)

    def test_fit_is_independent_of_held_out_labels(self):
        rows = fixture()
        first, _ = train_and_evaluate(rows)
        changed = copy.deepcopy(rows)
        for row in changed:
            if row["split"] == "test" and row["independent_review"]["verdict"] != "UNKNOWN":
                row["independent_review"]["verdict"] = (
                    "BENIGN" if row["independent_review"]["verdict"] == "ATTACK" else "ATTACK"
                )
        second, _ = train_and_evaluate(changed)
        self.assertEqual(first, second)

    def test_cross_group_leakage_is_rejected(self):
        rows = fixture()
        rows[-2]["asset_group"] = "train-group-0"
        with self.assertRaisesRegex(ValueError, "leakage"):
            train_and_evaluate(rows)

    def test_training_requires_two_classes(self):
        rows = fixture()
        for row in rows:
            if row["split"] == "train":
                row["independent_review"]["verdict"] = "BENIGN"
        with self.assertRaisesRegex(ValueError, "training cases per class"):
            train_and_evaluate(rows)

    def test_inference_rejects_unknown_or_post_action_feature(self):
        model, _ = train_and_evaluate(fixture())
        features = fixture()[0]["pre_action_features"]
        self.assertIsInstance(predict_probability(model, features), float)
        bad = dict(features, remediation_succeeded=True)
        with self.assertRaises(ValueError):
            predict_probability(model, bad)
        bad = dict(features, network_alert=None)
        with self.assertRaises(ValueError):
            predict_probability(model, bad)
        bad_model = dict(model, coefficients=[float("nan")] * 6)
        with self.assertRaises(ValueError):
            predict_probability(bad_model, features)

    def test_calibration_labels_do_not_change_fitted_model(self):
        original = fixture()
        baseline, _ = train_and_evaluate(original)
        altered = copy.deepcopy(original)
        for row in altered:
            if row["split"] == "calibration":
                row["independent_review"]["verdict"] = (
                    "BENIGN" if row["independent_review"]["verdict"] == "ATTACK" else "ATTACK"
                )
        again, _ = train_and_evaluate(altered)
        self.assertEqual(baseline, again)


if __name__ == "__main__":
    unittest.main()
