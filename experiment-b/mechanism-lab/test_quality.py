"""No-network unit tests of measured-only fault and repeat quality accounting."""
import unittest

from plan import ACTIONS, FAULTS_V31
from quality import quality_summary


class MeasuredQualityTests(unittest.TestCase):
    """Protect against reporting generator plans as independently observed data."""

    def rows(self):
        """Build controlled *unit-test-only* records with the declared group shape."""
        results = []
        for config in range(100):
            for action in ACTIONS:
                for repeat in range(3):
                    results.append({
                        "group": f"unit-config-{config}",
                        "action": action,
                        "fault": FAULTS_V31[config % len(FAULTS_V31)],
                        "partition": ("train" if config < 60 else
                                      "calibration" if config < 80 else "test"),
                        "label_security_exposure": float(
                            action == "monitor_only"
                        ),
                        "label_service_failure_fraction": (
                            repeat * 0.02 if action == "restart_enforcer" else 0.0
                        ),
                    })
        return results

    def test_counting_is_grouped_not_per_trial(self):
        """Exactly 400 configuration/action combinations are examined."""
        result = quality_summary(self.rows())
        self.assertEqual(result["measured_trials"], 1200)
        self.assertEqual(result["unique_configuration_action_groups"], 400)
        self.assertEqual(result["security_labels_vary_across_repeats"], 0)
        self.assertEqual(result["service_failure_labels_vary_across_repeats"], 100)
        self.assertFalse(result["ai_effectiveness_validated"])

    def test_missing_fault_family_is_rejected(self):
        """A manifest can never replace missing measured fault families."""
        rows = [r for r in self.rows() if r["fault"] != "consumer_paused"]
        with self.assertRaises(ValueError):
            quality_summary(rows)

    def test_missing_repeat_is_rejected(self):
        """Two actual measurements must not be treated as three."""
        rows = self.rows()
        rows.pop()
        with self.assertRaises(ValueError):
            quality_summary(rows)


if __name__ == "__main__":
    unittest.main()
