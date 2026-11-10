"""Tests for the AI research training pipeline.

Synthetic fixtures in these tests are not experimental results and are never
included in PREDICT-SHIELD published evaluation outputs.
"""
import tempfile
import unittest
from pathlib import Path

import numpy as np

from generate_manifest import ACTIONS
from train_action_model import (
    FEATURE_NAMES, checked_records, conformal_radius,
    feature_vector, train_and_report,
)


class ActionModelTrainingTests(unittest.TestCase):
    """Test leakage boundaries, calibration and baseline evaluation mechanics."""

    def make_example(self, group, split, action, fault, repeat):
        """Create one labeled unit-test fixture, never a live-lab measurement."""
        features = {
            "enforcement_points": 4, "stale_points": 2,
            "cache_ttl_ms": 50 + group * 13, "propagation_delay_ms": 20 + group * 17,
            "traffic_rps": 100 + group * 3, "dependency_depth": (group % 6) + 1,
            "redundancy": (group % 3) + 1,
        }
        return {
            "run_id": f"fake-{group}-{action}-{repeat}",
            "group": f"group-{group}", "split": split,
            "action_id": action, "fault_family": fault, "config": features,
            "initial_allowed_fraction": 0.5,
            "label_residual_exposure": float(action == "monitor_only"),
            "label_service_failure": float(action == "gateway_restrict") * 0.4,
        }

    def test_feature_vector_never_contains_post_action_label(self):
        """A change to the hidden oracle label cannot alter model features."""
        row = self.make_example(0, "train", "resync_policy", "stale_cache", 0)
        before = feature_vector(row)
        row["label_residual_exposure"] = 0.998
        row["label_service_failure"] = 0.997
        self.assertEqual(feature_vector(row), before)
        self.assertEqual(len(before), len(FEATURE_NAMES))

    def test_features_have_expected_one_hot_categorical_columns(self):
        """Exactly one fault family and one action column are active."""
        row = self.make_example(0, "train", "resync_policy", "stale_cache", 0)
        vector = feature_vector(row)
        self.assertEqual(sum(vector[8:14]), 1.0)
        self.assertEqual(sum(vector[14:]), 1.0)

    def test_conformal_radius_is_calibration_only(self):
        """A simple known residual array produces a conservative interval."""
        observations = np.array([0.0, 0.1, 0.2, 0.4], dtype=float)
        predictions = np.zeros(4, dtype=float)
        self.assertAlmostEqual(conformal_radius(observations, predictions), 0.4)

    def test_empty_or_incomplete_records_refuse_training(self):
        """A manifest without executed results cannot train the AI estimator."""
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                checked_records(Path(directory))

    def test_training_runs_on_disjoint_synthetic_unit_fixtures(self):
        """Fit and evaluate two models without reusing configuration groups."""
        examples = []
        for group in range(10):
            split = "train" if group < 6 else "calibration" if group < 8 else "test"
            fault = ("stale_cache", "lost_event")[group % 2]
            for repeat in range(3):
                for action in ACTIONS:
                    examples.append(self.make_example(group, split, action, fault, repeat))
        metrics = train_and_report(examples, seed=23)
        self.assertEqual(metrics["group_counts"], {
            "train": 6, "calibration": 2, "test": 2
        })
        self.assertIn("label_residual_exposure", metrics["targets"])
        self.assertIn("label_service_failure", metrics["targets"])
        self.assertEqual(metrics["targets"]["label_residual_exposure"]["held_out_count"], 24)
        self.assertTrue(metrics["not_production_validation"])


if __name__ == "__main__":
    unittest.main()
