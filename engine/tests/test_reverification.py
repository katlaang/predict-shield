import unittest

from predict_shield.reverification import Subject, schedule


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.items = [
            Subject("changed", last_verified_at=90, changed_at=95, risk=0.3),
            Subject("high-risk", last_verified_at=75, risk=0.95),
            Subject("old", last_verified_at=10, risk=0.1),
            Subject("recent", last_verified_at=99, risk=0.8),
        ]

    def test_fixed_interval_only_old(self):
        self.assertEqual([x.subject_id for x in schedule(self.items, now=100, budget=2,
                         policy="fixed", interval=60)], ["old"])

    def test_change_only_changed(self):
        self.assertEqual([x.subject_id for x in schedule(self.items, now=100, budget=2,
                         policy="change")], ["changed"])

    def test_adaptive_multiple_causes_and_budget(self):
        result = schedule(self.items, now=100, budget=2, policy="adaptive")
        self.assertEqual([x.subject_id for x in result], ["changed", "high-risk"])
        self.assertEqual(sum(x.units for x in result), 2)

    def test_no_false_verification_and_no_oracle(self):
        result = schedule(self.items, now=100, budget=3, policy="adaptive")
        self.assertTrue(result)
        self.assertFalse(any(hasattr(x, "verification_outcome") for x in result))

    def test_rejects_duplicate_and_future_observation(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            schedule([self.items[0], self.items[0]], now=100, budget=2, policy="fixed")
        with self.assertRaises(ValueError):
            schedule([Subject("future", 101, risk=0.5)], now=100, budget=1, policy="fixed")

    def test_cost_budget(self):
        items = [Subject("heavy", 0, risk=0.9, last_probe_cost=3),
                 Subject("light", 0, risk=0.8, last_probe_cost=1)]
        result = schedule(items, now=100, budget=2, policy="fixed")
        self.assertEqual([x.subject_id for x in result], ["light"])


if __name__ == "__main__":
    unittest.main()
