import copy
import unittest

from outage_interval_diagnostic import evaluate, interval_cost


def arm(action, witness, *, lower=0.1, upper=0.3,
        direct_allows=0, failed=1):
    return {
        "action": action,
        "witness_sha256": witness * 64,
        "policy_truth": "UNKNOWN",
        "verification_status": "INDETERMINATE",
        "observed_allow_count": direct_allows,
        "observed_deny_count": 4 - direct_allows,
        "unknown_target_count": 0,
        "timed_observations": {
            "schema": "predict-shield/outage-timed-observations/1",
            "policy_verification_from_this_measurement": "NOT_EVALUATED",
            "revoked_gateway_exposure": {
                "method": "monotonic_http_step_integral", "valid_probe_count": 6,
                "exposure_fraction_lower_bound": lower,
                "exposure_fraction_upper_bound": upper,
            },
            "authorized_protected": {
                "requests": 10, "non_200_requests": failed,
                "http_status_counts": {"200": 10 - failed, "403": failed}},
            "legitimate_endpoint": {
                "requests": 10, "non_200_requests": 0,
                "http_status_counts": {"200": 10}},
        },
    }


def sample_report():
    actions = ("resync_policy", "restart_enforcer", "gateway_restrict", "monitor_only")
    return {
        "schema": "predict-shield/v31-outage-action-observations/1",
        "physical_action_replays": 4, "decision_value_computed": False,
        "v31_feasibility_evaluated": False,
        "results": [arm(a, chr(ord("a") + i)) for i, a in enumerate(actions)],
    }


class OutageIntervalTests(unittest.TestCase):
    def test_real_cost_bounds_preserve_unknown_authority_risk(self):
        result = evaluate(sample_report(), error_budget_requests=25,
                          restart_permitted=True)
        item = result["action_intervals"][0]
        self.assertAlmostEqual(item["cost_lower_bound"], .06)
        self.assertAlmostEqual(item["cost_upper_bound"], .41)
        self.assertEqual(result["status"], "EXPLORATORY_INTERVALS_ONLY")
        self.assertIsNone(result["unique_definite_best_action"])
        self.assertTrue(result["not_a_frozen_v31_primary_utility"])

    def test_direct_allow_raises_minimum_risk(self):
        a = arm("monitor_only", "a", lower=0, upper=0, direct_allows=1, failed=0)
        item = interval_cost(a, error_budget_requests=25)
        self.assertAlmostEqual(item["cost_lower_bound"], .25)
        self.assertAlmostEqual(item["cost_upper_bound"], .25)

    def test_unknown_direct_targets_do_not_prove_success(self):
        a = arm("monitor_only", "a", lower=0, upper=0, direct_allows=0, failed=0)
        a["unknown_target_count"] = 4
        a["observed_deny_count"] = 0
        result = interval_cost(a, error_budget_requests=25)
        self.assertEqual(result["unresolved_policy_indicator_upper_bound"], 1)
        self.assertEqual(result["cost_upper_bound"], .25)

    def test_eligibility_rejects_restart_without_changing_replays(self):
        result = evaluate(sample_report(), error_budget_requests=25,
                          restart_permitted=False)
        self.assertNotIn("restart_enforcer", result["feasible_actions_for_offline_comparison"])
        self.assertEqual(len(result["action_intervals"]), 4)

    def test_missing_action_and_reused_witness_are_rejected(self):
        r = sample_report()
        r["results"].pop()
        with self.assertRaisesRegex(ValueError, "four distinct"):
            evaluate(r, error_budget_requests=25, restart_permitted=True)
        r = sample_report()
        r["results"][1]["witness_sha256"] = r["results"][0]["witness_sha256"]
        with self.assertRaisesRegex(ValueError, "independent policy witnesses"):
            evaluate(r, error_budget_requests=25, restart_permitted=True)

    def test_refuse_false_verification_and_unfounded_numerators(self):
        r = sample_report()
        r["results"][0]["verification_status"] = "VERIFIED"
        with self.assertRaisesRegex(ValueError, "VERIFIED oracle"):
            evaluate(r, error_budget_requests=25, restart_permitted=True)
        r = sample_report()
        r["results"][0]["timed_observations"]["authorized_protected"]["non_200_requests"] = 11
        with self.assertRaisesRegex(ValueError, "denominator"):
            evaluate(r, error_budget_requests=25, restart_permitted=True)

    def test_strict_interval_dominance_not_overlap(self):
        r = sample_report()
        # Lower-bound exposure of 1 proves at least a 0.5 exposure cost.
        # Baseline action's worst-case cost 0.25 remains below that.
        for a in r["results"][1:]:
            a["timed_observations"]["revoked_gateway_exposure"].update({
                "exposure_fraction_lower_bound": 1.0,
                "exposure_fraction_upper_bound": 1.0})
        top = r["results"][0]
        top["timed_observations"]["revoked_gateway_exposure"].update({
            "exposure_fraction_lower_bound": 0.0,
            "exposure_fraction_upper_bound": 0.0})
        top["timed_observations"]["authorized_protected"] = {
            "requests": 10, "non_200_requests": 0, "http_status_counts": {"200": 10}}
        report = evaluate(r, error_budget_requests=25, restart_permitted=True)
        self.assertEqual(report["unique_definite_best_action"], "resync_policy")

    def test_nan_exposure_and_zero_budget_rejected(self):
        r = sample_report()
        r["results"][0]["timed_observations"]["revoked_gateway_exposure"][
            "exposure_fraction_upper_bound"] = float("nan")
        with self.assertRaises(ValueError):
            evaluate(r, error_budget_requests=25, restart_permitted=True)
        with self.assertRaises(ValueError):
            evaluate(sample_report(), error_budget_requests=0,
                     restart_permitted=True)


if __name__ == "__main__":
    unittest.main()
