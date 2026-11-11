"""No-network validation of measured-only model training and lookup baselines.

Any in-memory synthetic examples here are unit-test fixtures, not collected
Experiment B measurements or publishable machine-learning results.
"""
import tempfile
import unittest
from pathlib import Path

from plan import ACTIONS, create_plan
from train import load_executed_dataset, to_features, train_evaluate


class MeasuredModelTrainingTests(unittest.TestCase):
    """Require separated dataset streams and prohibit post-outcome feature leakage."""

    def test_manifest_alone_cannot_train(self):
        """The trainer rejects a directory without 1,200 measured trial records."""
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                load_executed_dataset(Path(directory))

    def test_labels_do_not_change_pre_action_features(self):
        """Oracle or outcome labels must never enter a predictor input vector."""
        row = {
            "action": ACTIONS[0], "fault": "loss", "target": "enforcer-b",
            "pre_action": {
                "cache_ttl_ms": 5000, "event_delay_ms": 200,
                "requested_rps": 20, "initial_gateway_allowed_fraction": 1/3,
            },
            "label_security_exposure": 1.0,
            "label_service_failure_fraction": 0.5,
        }
        baseline = to_features(row)
        row["label_security_exposure"] = 0.0
        row["label_service_failure_fraction"] = 0.0
        self.assertEqual(to_features(row), baseline)

    def test_training_rejects_group_overlap(self):
        """Identical configuration IDs cannot occur across evaluation partitions."""
        row = {
            "group": "same", "partition": "train", "action": ACTIONS[0],
            "fault": "loss", "target": "enforcer-b",
            "pre_action": {
                "cache_ttl_ms": 5000, "event_delay_ms": 200,
                "requested_rps": 20, "initial_gateway_allowed_fraction": 0.5,
            },
            "label_security_exposure": 1.0,
            "label_service_failure_fraction": 0.5,
        }
        other = dict(row, partition="test")
        with self.assertRaises(ValueError):
            train_evaluate([row, other])


if __name__ == "__main__":
    unittest.main()
