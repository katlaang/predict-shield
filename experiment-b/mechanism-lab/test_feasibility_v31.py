import unittest

from feasibility_v31 import evaluate

COMMIT = "a" * 40


def instance(config, stratum, repeat, costs=None):
    return {
        "schema": "predict-shield/v31-audited-action-costs/1",
        "measurement_verified": True,
        "four_streams_complete": True,
        "partition": "pilot",
        "source_commit": COMMIT,
        "configuration_id": f"v31-pilot-{config}",
        "stratum": stratum,
        "repeat": repeat,
        "eligible_actions": ["resync_policy","restart_enforcer",
                             "gateway_restrict","monitor_only"],
        "action_costs": costs or {"resync_policy": 0.2, "restart_enforcer": 0.1,
                                  "gateway_restrict": 0.5, "monitor_only": 0.3},
    }


class FeasibilityGateTests(unittest.TestCase):
    def sample(self):
        return ([instance("001","SIMPLE",i) for i in (0,1)]
                + [instance("002","INTERACTION",i) for i in (0,1)]
                + [instance("003","PARTIAL_VISIBILITY",0,
                            {"resync_policy":0.3,"restart_enforcer":0.2,
                             "gateway_restrict":0.6,"monitor_only":0.1}),
                   instance("003","PARTIAL_VISIBILITY",1,
                            {"resync_policy":0.3,"restart_enforcer":0.1,
                             "gateway_restrict":0.6,"monitor_only":0.2})])

    def test_pilot_reports_rates_without_ai_claim(self):
        result = evaluate(self.sample())
        self.assertEqual(result["pilot_configuration_groups"],3)
        self.assertEqual(result["paired_decision_instances"],6)
        self.assertEqual(result["mismatched_decisions"],3)
        self.assertEqual(result["decision_diversity_denominator"],3)
        self.assertEqual(result["repeat_level_mismatches_descriptive_only"],6)
        self.assertEqual(result["partial_visibility_unique_optima"], [])
        self.assertFalse(result["trained_ai_evaluated"])
        self.assertTrue(result["precision_not_a_model_power_calculation"])

    def test_repeats_do_not_fabricate_pv_optimal_diversity(self):
        rows = self.sample()
        result = evaluate(rows)
        # The two PV repeats favor different actions, but the group-level
        # means tie: this is NOT evidence of two independent PV optima.
        self.assertEqual(result["partial_visibility_unique_optima"], [])
        self.assertIn("insufficient_unique_partial_visibility_optimal_actions",
                      result["failures"])

    def test_group_decision_differs_from_repeat_majority(self):
        rows = self.sample()
        # Group 001 has one repeat favoring resync and the other favoring
        # monitor very strongly; group mean monitor wins, even though raw
        # repeat-level counts are mixed.
        rows[0]["action_costs"] = {
            "resync_policy": 0.0, "restart_enforcer": 0.2,
            "gateway_restrict": 0.5, "monitor_only": 0.1}
        rows[1]["action_costs"] = {
            "resync_policy": 0.5, "restart_enforcer": 0.6,
            "gateway_restrict": 0.8, "monitor_only": 0.0}
        result = evaluate(rows)
        group = next(x for x in result["per_group"] if x["configuration_id"]=="v31-pilot-001")
        self.assertEqual(group["group_optimal_actions"], ["monitor_only"])
        self.assertEqual(result["decision_diversity_denominator"],3)

    def test_rejects_eligibility_changing_across_repeats(self):
        rows = self.sample()
        rows[1]["eligible_actions"] = ["resync_policy","gateway_restrict","monitor_only"]
        with self.assertRaisesRegex(ValueError, "Action eligibility varied"):
            evaluate(rows)

    def test_refuse_missing_repeat(self):
        with self.assertRaises(ValueError):
            evaluate(self.sample()[:-1])

    def test_refuse_nonpilot_outcomes(self):
        rows = self.sample()
        rows[0]["partition"] = "test"
        with self.assertRaisesRegex(ValueError,"Feasibility cannot inspect"):
            evaluate(rows)

    def test_refuse_unverified_fabricated_record(self):
        rows = self.sample()
        rows[0]["measurement_verified"] = False
        with self.assertRaisesRegex(ValueError,"Not independently audited"):
            evaluate(rows)

    def test_ties_do_not_count_as_diversity(self):
        rows = self.sample()
        for row in rows:
            row["action_costs"] = {a: 0.2 for a in row["action_costs"]}
        report = evaluate(rows)
        self.assertEqual(report["decision_diversity"],0)
        self.assertEqual(report["status"],"FEASIBILITY_INCONCLUSIVE")
        self.assertIn("insufficient_fixed_policy_decision_diversity",
                      report["failures"])

    def test_refuse_unmeasured_action(self):
        rows = self.sample()
        rows[0]["action_costs"].pop("gateway_restrict")
        with self.assertRaisesRegex(ValueError,"Every action must be measured"):
            evaluate(rows)


if __name__ == "__main__":
    unittest.main()
