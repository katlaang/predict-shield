"""No-network tests for exploratory held-out tuned-rule pilot assessment."""
import unittest

from decision_eval import ACTIONS
from pilot_regret import exploratory_leave_one_config_out


class TunedPilotCrossfitTests(unittest.TestCase):
    """Keep pilot threshold fitting and scoring in different configurations."""

    def test_each_pilot_configuration_is_held_out_completely(self):
        """A threshold never sees either repeat from its evaluated config."""
        paired = {}
        for i in range(4):
            for repeat in range(2):
                actions = {}
                for action in ACTIONS:
                    actions[action] = {
                        "action": action,
                        "restart_permitted": i != 3,
                        "absolute_error_budget_requests": 25,
                        "pre_action": {
                            "cache_ttl_ms": 9000 + 200 * i,
                            "requested_rps": 20 + 10 * i,
                            "initial_gateway_allowed_fraction": .25,
                            "operator_revision_spread": 1,
                        },
                        "label_path_exposure": float(
                            action in ("monitor_only", "resync_policy")),
                        "label_security_exposure": float(
                            action in ("monitor_only", "gateway_restrict")),
                        "label_absolute_failed_requests": float(
                            action == "gateway_restrict") * 12,
                    }
                paired[(f"toy-config-{i}", repeat)] = actions
        result = exploratory_leave_one_config_out(paired)
        self.assertEqual(result["grid_size"], 216)
        self.assertEqual(result["pilot_independent_configurations"], 4)
        self.assertTrue(result["not_ai_model_comparison"])
        self.assertTrue(result["not_the_frozen_60_group_tuned_baseline"])
        self.assertTrue(all(
            fold["fitted_on_other_configuration_groups"] == 3
            and fold["repeat_count"] == 2
            for fold in result["heldout_folds"]
        ))


if __name__ == "__main__":
    unittest.main()
