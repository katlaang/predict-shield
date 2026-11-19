"""Incident-learning contract tests: missing and deceptive labels fail closed."""
from __future__ import annotations

import copy
import unittest

from predict_shield.incident_feedback import validated_feedback, score_detection, SCHEMA, FEATURES


def make(ident, split, asset, verdict, *, features=None):
    return {"schema": SCHEMA, "incident_id": ident, "asset_group": asset, "split": split,
            "detected_at": "2026-11-18T18:00:00Z", "alert_evidence_sha256": "a" * 64,
            "signal_source_id": "signed-suricata",
            "pre_action_features": features if features is not None else {
                "network_alert": True, "endpoint_alert": False,
                "known_vulnerability": False, "observed_remote_access": True,
                "critical_service_count": 1, "independent_source_count": 1},
            "independent_review": {
                "verdict": verdict, "reviewer_id": "reviewer-ot",
                "reviewed_at": "2026-11-18T19:00:00Z",
                "independent_evidence_sha256": "b" * 64}}


class IncidentFeedbackTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            make("train-attack", "train", "substation-01", "ATTACK"),
            make("train-benign", "train", "substation-01", "BENIGN"),
            make("calibration-benign", "calibration", "substation-02", "BENIGN"),
            make("test-attack", "test", "substation-03", "ATTACK"),
            make("test-benign", "test", "substation-03", "BENIGN"),
            make("test-unknown", "test", "substation-03", "UNKNOWN"),
        ]

    def test_independently_reviewed_rows_and_unknown_exclusion(self):
        prepared = validated_feedback(self.rows)
        self.assertEqual(prepared["included"], 5)
        self.assertEqual(prepared["excluded_unknown"], 1)
        self.assertEqual(len(prepared["sha256"]), 64)
        self.assertEqual(list(prepared["rows"][0]["features"]), list(FEATURES))
        self.assertNotIn("label_attack", prepared["rows"][0]["features"])

    def test_measured_labels_not_promoted_to_field_truth(self):
        prepared = validated_feedback(self.rows)
        result = score_detection([
            {"incident_id": "test-attack", "predict_attack": True},
            {"incident_id": "test-benign", "predict_attack": True},
        ], prepared)
        self.assertEqual((result["TP"], result["FP"], result["FN"], result["TN"]), (1, 1, 0, 0))
        self.assertEqual(result["precision"], .5)
        self.assertEqual(result["recall"], 1.0)
        self.assertEqual(result["false_positive_rate"], 1.0)
        self.assertFalse(result["field_detection_accuracy_established"])

    def test_wrong_label_author_and_evidence_digest_rejected(self):
        for change in (
            lambda row: row["independent_review"].update(reviewer_id="signed-suricata"),
            lambda row: row["independent_review"].update(independent_evidence_sha256="a" * 64),
            lambda row: row["independent_review"].update(reviewed_at="2026-11-18T17:00:00Z"),
        ):
            with self.subTest(change=change):
                rows = copy.deepcopy(self.rows)
                change(rows[0])
                with self.assertRaises(ValueError):
                    validated_feedback(rows)

    def test_no_cross_split_group_leakage(self):
        rows = copy.deepcopy(self.rows)
        rows[3]["asset_group"] = "substation-01"
        with self.assertRaisesRegex(ValueError, "leakage"):
            validated_feedback(rows)

    def test_duplicate_and_invalid_labels_rejected(self):
        for bad in ("ATTACKED", None):
            rows = copy.deepcopy(self.rows)
            rows[0]["independent_review"]["verdict"] = bad
            with self.assertRaises(ValueError):
                validated_feedback(rows)
        rows = copy.deepcopy(self.rows)
        rows[0]["incident_id"] = rows[1]["incident_id"]
        with self.assertRaises(ValueError):
            validated_feedback(rows)

    def test_post_action_outcomes_not_allowed_as_training_features(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["pre_action_features"]["remediation_verified"] = True
        with self.assertRaisesRegex(ValueError, "exact pre-action"):
            validated_feedback(rows)

    def test_missing_and_non_boolean_features_rejected(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["pre_action_features"]["network_alert"] = 1
        with self.assertRaises(ValueError):
            validated_feedback(rows)

    def test_no_unknown_or_extra_test_prediction_accepted(self):
        prepared = validated_feedback(self.rows)
        for predictions in (
            [{"incident_id": "test-attack", "predict_attack": True}],
            [{"incident_id": "test-attack", "predict_attack": True},
             {"incident_id": "test-unknown", "predict_attack": False}],
            [{"incident_id": "test-attack", "predict_attack": True},
             {"incident_id": "test-attack", "predict_attack": False}],
        ):
            with self.subTest(predictions=predictions):
                with self.assertRaises(ValueError):
                    score_detection(predictions, prepared)

    def test_structural_provenance_not_authentication(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["independent_review"]["reviewer_id"] = "invented-person"
        result = validated_feedback(rows)
        self.assertIn("not authenticated", result["claim"])


if __name__ == "__main__":
    unittest.main()
