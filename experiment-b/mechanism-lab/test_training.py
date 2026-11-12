"""No-network validation of measured-only model training and lookup baselines.

Any in-memory synthetic examples here are unit-test fixtures, not collected
Experiment B measurements or publishable machine-learning results.
"""
import hashlib
import tempfile
import unittest
from pathlib import Path

from plan import ACTIONS, create_plan
from train import load_executed_dataset, to_features, train_evaluate, grouped_conformal_radius
from model_adapter import load_local_bundle


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
                "requested_rps": 20, "gateway_visible_enforcer_count": 3,
                "initial_gateway_allowed_fraction": 1/3,
            },
            "label_security_exposure": 1.0,
            "label_service_failure_fraction": 0.5,
        }
        baseline = to_features(row)
        row["label_security_exposure"] = 0.0
        row["label_service_failure_fraction"] = 0.0
        self.assertEqual(to_features(row), baseline)

    def test_synthetic_training_calibration_export_and_checksum(self):
        """Exercise model fitting on toy fixtures without implying research results."""
        examples = []
        for group in range(12):
            partition = ("train" if group < 8 else
                         "calibration" if group < 10 else "test")
            for repeat in range(3):
                for index, action in enumerate(ACTIONS):
                    examples.append({
                        "group": "unit-" + str(group),
                        "repeat": repeat,
                        "partition": partition,
                        "action": action,
                        "fault": ("loss", "delay", "duplicate", "reorder")[group % 4],
                        "target": ("enforcer-a", "enforcer-b", "enforcer-c")[group % 3],
                        "pre_action": {
                            "cache_ttl_ms": 3000 + group * 100,
                            "event_delay_ms": group * 100,
                            "requested_rps": 15 + group,
                            "gateway_visible_enforcer_count": 3,
                            "initial_gateway_allowed_fraction": (group % 3) / 3,
                        },
                        "label_security_exposure": float(index == 3),
                        "label_path_exposure": float(index in (0, 3)),
                        "label_service_failure_fraction": float(index == 2) * 0.4,
                    })
        with tempfile.TemporaryDirectory() as directory:
            model_file = Path(directory) / "lab-model.joblib"
            report = train_evaluate(examples, export_path=model_file)
            self.assertTrue(model_file.is_file())
            self.assertEqual(report["trial_counts"]["test"], 24)
            self.assertIn("label_security_exposure", report["metrics"])
            digest = hashlib.sha256(model_file.read_bytes()).hexdigest()
            bundle = load_local_bundle(model_file, trusted_sha256=digest)
            self.assertEqual(bundle["training_group_count"], 8)
            with self.assertRaises(ValueError):
                load_local_bundle(model_file, trusted_sha256="0" * 64)

    def test_injected_fault_information_cannot_change_training_features(self):
        """Changing hidden fault labels cannot change operational model input."""
        row = {
            "action": ACTIONS[0], "fault": "loss", "target": "enforcer-a",
            "pre_action": {
                "cache_ttl_ms": 6000, "requested_rps": 30, "gateway_visible_enforcer_count": 3,
                "initial_gateway_allowed_fraction": .3,
            },
        }
        before = to_features(row)
        row.update(fault="reorder", target="enforcer-c")
        self.assertEqual(before, to_features(row))

    def test_conformal_calibration_uses_configuration_max_residual(self):
        """Correlated repeats must not inflate the independent sample count."""
        truth = [0, 0, 0, 0, 0, 0]
        predicted = [0, .1, .2, .1, .4, .7]
        groups = ["cfg-a"] * 3 + ["cfg-b"] * 3
        self.assertAlmostEqual(
            grouped_conformal_radius(truth, predicted, groups), .7
        )
        with self.assertRaises(ValueError):
            grouped_conformal_radius(truth, predicted, ["cfg-a"])

    def test_training_rejects_group_overlap(self):
        """Identical configuration IDs cannot occur across evaluation partitions."""
        row = {
            "group": "same", "partition": "train", "action": ACTIONS[0],
            "fault": "loss", "target": "enforcer-b",
            "pre_action": {
                "cache_ttl_ms": 5000, "event_delay_ms": 200,
                "requested_rps": 20, "gateway_visible_enforcer_count": 3,
                "initial_gateway_allowed_fraction": 0.5,
            },
            "label_security_exposure": 1.0,
            "label_service_failure_fraction": 0.5,
        }
        other = dict(row, partition="test")
        with self.assertRaises(ValueError):
            train_evaluate([row, other])


if __name__ == "__main__":
    unittest.main()
