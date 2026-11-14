"""Synthetic unit-contract tests: NOT measured research or model success."""
import unittest
from train_group_stability import grouped_stability, training_rows, SEEDS
from pathlib import Path

ACTIONS = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")


def synthetic_training_fixture():
    rows = []
    for g in range(60):
        for repeat in (0, 1, 2):
            for action in ACTIONS:
                rows.append({
                    "group": "synthetic-group-%03d" % g,
                    "partition": "train",
                    "repeat": repeat,
                    "action": action,
                    "restart_permitted": g % 2 == 0,
                    "absolute_error_budget_requests": 25,
                    "pre_action": {
                        "cache_ttl_ms": 5000,
                        "requested_rps": 25,
                        "gateway_visible_enforcer_count": 4,
                        "initial_gateway_allowed_fraction": .2,
                        "routing_profile": "balanced",
                        "operator_observed_count": 4,
                        "operator_missing_count": 0,
                        "operator_revision_spread": 1,
                    },
                    "label_path_exposure": 0.0 if action == "monitor_only" else .2,
                    "label_security_exposure": 0.0,
                    "label_absolute_failed_requests": 0,
                })
    return rows


class TrainStabilityContractTests(unittest.TestCase):
    def test_missing_five_real_archives_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "five audited"):
            training_rows([])

    def test_reject_nontraining_partitions(self):
        rows = synthetic_training_fixture()
        rows[0]["partition"] = "test"
        with self.assertRaisesRegex(ValueError, "training groups"):
            grouped_stability(rows, seeds=(101,), estimators=16)

    def test_reproducible_group_cv_and_no_superiority_claim(self):
        rows = synthetic_training_fixture()
        a = grouped_stability(rows, seeds=(101,), estimators=16)
        b = grouped_stability(rows, seeds=(101,), estimators=16)
        self.assertEqual(a, b)
        self.assertEqual(a["group_validation_folds"], 5)
        self.assertEqual(a["train_only_independent_groups"], 60)
        self.assertFalse(a["test_or_calibration_used_for_training_selection"])
        self.assertFalse(a["confirmatory_superiority_established"])
        self.assertEqual(
            a["folds_ai_better_than_fixed_monitor"] +
            a["folds_ai_worse_than_fixed_monitor"] +
            a["folds_tied"], 5)


if __name__ == "__main__":
    unittest.main()
