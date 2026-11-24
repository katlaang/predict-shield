"""Regression: non-alerting attack between two false alerts cannot redeem incident."""
import unittest
import numpy as np
from corrected_incident_accounting import incident_counts


class IncidentAccountingTests(unittest.TestCase):
    def test_benign_alerts_with_nonalerting_attack_between(self):
        got = incident_counts([0.0, 1.0, 1.5], [True, False, True], [False, True, False])
        self.assertEqual(got, {"incidents": 1, "true_incidents": 0, "false_incidents": 1})

    def test_incident_true_only_when_attack_alerted(self):
        got = incident_counts([0.0, 1.0, 1.5], [True, True, True], [False, True, False])
        self.assertEqual(got, {"incidents": 1, "true_incidents": 1, "false_incidents": 0})

    def test_separate_groups(self):
        got = incident_counts([0.0, 3.0, 6.0], [True, True, True], [False, True, False])
        self.assertEqual(got, {"incidents": 3, "true_incidents": 1, "false_incidents": 2})

    def test_shape_rejected(self):
        with self.assertRaises(ValueError):
            incident_counts([0.0], [True], [True, False])


if __name__ == "__main__":
    unittest.main()
