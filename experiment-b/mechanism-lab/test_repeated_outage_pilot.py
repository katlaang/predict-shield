"""Contract tests use obvious fake data; they are not physical research results."""
import copy
import unittest

from repeated_outage_pilot import ACTIONS, SCHEMA, aggregate, summarize


def physical_fixture():
    results = []
    intervals = []
    for index, action in enumerate(ACTIONS):
        results.append({
            "action": action,
            "action_observation": {"action_status": "UNIT_TEST_ONLY"},
            "witness_sha256": chr(ord("a")+index)*64,
            "policy_truth": "UNKNOWN",
            "verification_status": "INDETERMINATE",
            "observed_allow_count": 1,
            "observed_deny_count": 2,
            "unknown_target_count": 1,
            "timed_observations": {
                "revoked_gateway_exposure": {
                    "valid_probe_count": 3,
                    "exposure_seconds_lower_bound": 1.0,
                    "exposure_seconds_upper_bound": 2.0,
                    "exposure_fraction_lower_bound": .166,
                    "exposure_fraction_upper_bound": .333,
                },
                "authorized_protected": {"requests": 5, "non_200_requests": 1},
                "legitimate_endpoint": {"requests": 6, "non_200_requests": 0},
            }
        })
        intervals.append({"action": action, "cost_lower_bound": .1, "cost_upper_bound": .4})
    return (
        {"schema": "predict-shield/v31-outage-action-observations/1",
         "physical_action_replays": 4, "decision_value_computed": False,
         "v31_feasibility_evaluated": False, "results": results},
        {"status": "EXPLORATORY_INTERVALS_ONLY",
         "not_v31_feasibility_or_campaign_authorization": True,
         "feasible_actions_for_offline_comparison": [
            "restart_enforcer", "gateway_restrict", "monitor_only"],
         "unique_definite_best_action": None,
         "action_intervals": intervals}
    )


class RepeatedPilots(unittest.TestCase):
    def test_only_full_physical_claims_are_accepted(self):
        raw, diagnostic = physical_fixture()
        batch = summarize(raw, diagnostic)
        data = aggregate([batch], "1"*40)
        self.assertEqual(data["schema"], SCHEMA)
        self.assertEqual(data["physical_action_replays"], 4)
        self.assertEqual(data["by_action"]["monitor_only"]["authorized_attempts"], 5)
        self.assertFalse(data["ai_action_model_trained_or_tested"])
        self.assertFalse(data["critical_infrastructure_operator_pilot"])
        self.assertEqual(data["independent_fault_configuration_count"], 1)

    def test_duplicate_witness_across_repeat_batches_is_rejected(self):
        raw, diagnostic = physical_fixture()
        batch = summarize(raw, diagnostic)
        with self.assertRaisesRegex(ValueError, "Reused witnessed"):
            aggregate([batch, copy.deepcopy(batch)], "1"*40)

    def test_no_false_verification(self):
        raw, diagnostic = physical_fixture()
        raw["results"][1]["verification_status"] = "VERIFIED"
        with self.assertRaisesRegex(ValueError, "Invalid independent"):
            summarize(raw, diagnostic)

    def test_incomplete_arm_rejected(self):
        raw, diagnostic = physical_fixture()
        raw["results"].pop()
        with self.assertRaisesRegex(ValueError, "Missing physical action arm"):
            summarize(raw, diagnostic)

    def test_missing_actual_probes_rejected(self):
        raw, diagnostic = physical_fixture()
        raw["results"][0]["timed_observations"]["revoked_gateway_exposure"][
            "valid_probe_count"] = 1
        with self.assertRaisesRegex(ValueError, "Invalid independent"):
            summarize(raw, diagnostic)

    def test_unsupported_planned_results_rejected(self):
        raw, diagnostic = physical_fixture()
        raw["decision_value_computed"] = True
        with self.assertRaisesRegex(ValueError, "Not a complete physical"):
            summarize(raw, diagnostic)


if __name__ == "__main__":
    unittest.main()
