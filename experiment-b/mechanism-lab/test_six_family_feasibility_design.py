import unittest
from collections import Counter

from six_family_feasibility_design import ACTIONS, FAULTS, SCHEMA, STRATA, build, validate


class SixFamilyFeasibilityDesignTests(unittest.TestCase):
    def test_balanced_groups_never_report_execution(self):
        configs, trials = build()
        self.assertEqual((len(configs), len(trials)), (18, 144))
        self.assertEqual(Counter(x["fault_mode"] for x in configs),
                         dict.fromkeys(FAULTS, 3))
        self.assertEqual(Counter(x["complexity_stratum"] for x in configs),
                         dict.fromkeys(STRATA, 6))
        self.assertEqual(Counter(x["action_id"] for x in trials),
                         dict.fromkeys(ACTIONS, 36))
        self.assertTrue(all(x["execution_status"] == "NOT_AUTHORIZED_NOT_EXECUTED"
                            and x["schema"] == SCHEMA for x in configs + trials))
        for x in configs:
            if x["fault_mode"] == "authority_outage":
                self.assertEqual(x["policy_semantics"],
                                 "HISTORICAL_WITNESS_INTERVAL_UNKNOWN_LIVE_AUTHORITY")

    def test_reproducible_distinct_design(self):
        self.assertEqual(build(42), build(42))
        self.assertNotEqual(build(42), build(43))

    def test_rejects_fake_execution(self):
        configs, trials = build()
        trials[0]["execution_status"] = "COMPLETE"
        with self.assertRaisesRegex(ValueError, "falsely executed"):
            validate(configs, trials)

    def test_rejects_missing_arm(self):
        configs, trials = build()
        with self.assertRaises(ValueError):
            validate(configs, trials[:-1])


if __name__ == "__main__":
    unittest.main()
