import unittest
from collections import Counter

from plan_v31 import ACTIONS, COUNT, FAULTS, SCHEMA, STRATA, build, validate


class V31PlanningTests(unittest.TestCase):
    def test_exact_count_balanced_and_disjoint(self):
        configs, trials = build()
        self.assertEqual((len(configs), len(trials)), (150, 1200))
        self.assertEqual(Counter(c["partition"] for c in configs),
                         {"train": 90, "calibration": 30, "test": 30})
        self.assertEqual(set(Counter(c["fault_mode"] for c in configs).values()), {25})
        self.assertEqual(set(Counter(c["complexity_stratum"] for c in configs).values()), {50})
        self.assertEqual(len({t["run_id"] for t in trials}), 1200)
        self.assertTrue(all(t["execution_status"] == "PLANNED_NOT_EXECUTED"
                            and t["schema"] == SCHEMA for t in trials))
        for fault in FAULTS:
            self.assertEqual(set(c["complexity_stratum"] for c in configs
                                 if c["fault_mode"] == fault), set(STRATA))

    def test_repeat_and_reproducibility(self):
        a, t = build(42)
        b, u = build(42)
        self.assertEqual((a, t), (b, u))
        self.assertNotEqual(build(43)[0], a)
        self.assertEqual(Counter(x["action_id"] for x in t), dict.fromkeys(ACTIONS, 300))

    def test_rejects_misrepresented_measured_trial(self):
        c, t = build()
        t[0]["execution_status"] = "COMPLETE"
        with self.assertRaises(ValueError):
            validate(c, t)

    def test_rejects_cross_partition(self):
        c, t = build()
        t[0]["partition"] = "wrong"
        with self.assertRaises(ValueError):
            validate(c, t)


if __name__ == "__main__":
    unittest.main()
