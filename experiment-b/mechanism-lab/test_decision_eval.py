"""Tests for hindsight regret accounting without empirical effectiveness claims."""
import unittest

from decision_eval import ACTIONS, engineering_rule, evaluate_regret, observed_utility


class DecisionRegretTests(unittest.TestCase):
    """Verify decision baselines cannot see hindsight labels when choosing actions."""

    def cases(self):
        """Generate two toy test groups containing all four measured-action slots."""
        rows = []
        predictions = {}
        for group in ("toy-a", "toy-b"):
            for repeat in range(3):
                for action in ACTIONS:
                    row = {
                        "group": group, "repeat": repeat,
                        "action": action,
                        "pre_action": {
                            "initial_gateway_allowed_fraction": 0.5,
                            "cache_ttl_ms": 9000,
                        },
                        "label_path_exposure": float(action == "resync_policy"),
                        "label_security_exposure": float(action == "gateway_restrict"),
                        "label_service_failure_fraction": float(action == "restart_enforcer") * 0.2,
                    }
                    rows.append(row)
                    predictions[(group, repeat, action)] = {
                        k: row[k] for k in (
                            "label_path_exposure",
                            "label_security_exposure",
                            "label_service_failure_fraction",
                        )
                    }
        return rows, predictions

    def test_hindsight_regret_uses_actual_outcomes_only_for_scoring(self):
        """Fixed resync has positive regret in this unit-test fixture."""
        rows, predictions = self.cases()
        report = evaluate_regret(rows, predictions)
        self.assertEqual(report["decision_instances"], 6)
        self.assertEqual(report["independent_configuration_groups"], 2)
        self.assertEqual(report["policies"]["model"]["mean_hindsight_regret"], 0)
        self.assertGreater(report["policies"]["fixed_resync"]["mean_hindsight_regret"], 0)
        self.assertFalse(report["actions_executed_by_model"])

    def test_predeclared_engineer_rule_excludes_hidden_fault(self):
        """Changing a hidden fault label must not alter the engineering baseline."""
        value = self.cases()[0][0]
        before = engineering_rule(value)
        value["fault"] = "loss"
        value["target"] = "enforcer-hidden"
        self.assertEqual(engineering_rule(value), before)

    def test_missing_candidate_prediction_refuses_report(self):
        """A missing model forecast cannot be filled from observed truth."""
        rows, predictions = self.cases()
        predictions.pop(next(iter(predictions)))
        with self.assertRaises(ValueError):
            evaluate_regret(rows, predictions)

    def test_outcome_normalization_is_mandatory(self):
        """Out-of-range risk or service failure measurements invalidate regret."""
        row = self.cases()[0][0]
        row["label_service_failure_fraction"] = 1.2
        with self.assertRaises(ValueError):
            observed_utility(row)


if __name__ == "__main__":
    unittest.main()
