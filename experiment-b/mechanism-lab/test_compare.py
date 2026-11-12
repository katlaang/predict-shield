"""Tests for observed paired comparisons with configuration-level uncertainty."""
import unittest

from compare import confidence_intervals, paired_differences
from plan import ACTIONS


class MeasuredComparisonTests(unittest.TestCase):
    """Ensure paired baseline comparisons never mistake repeats for new groups."""

    def sample(self):
        """Create toy unit-test rows without implying empirical findings."""
        output = []
        for group in ("c-1", "c-2"):
            for repeat in range(3):
                for action in ACTIONS:
                    output.append({
                        "group": group,
                        "partition": "test",
                        "action": action,
                        "label_security_exposure": float(action == "monitor_only"),
                        "label_service_failure_fraction": (
                            .5 if action == "gateway_restrict" else .0
                        ),
                    })
        return output

    def test_grouped_action_comparison(self):
        """Four paired actions over six repeats still represent two groups."""
        comparison = paired_differences(self.sample(), "test")
        self.assertEqual(comparison["configuration_groups"], 2)
        self.assertEqual(len(comparison["paired"]["resync_policy"]), 2)
        report = confidence_intervals(comparison, replicates=100, seed=42)
        self.assertEqual(report["reference_action"], "monitor_only")
        result = report["action_comparisons"]["resync_policy"]["exposure_difference"]
        self.assertEqual(result["observed_mean_difference"], -1.0)
        self.assertEqual(result["cluster_bootstrap_lower_95"], -1.0)
        self.assertEqual(result["configuration_groups"], 2)

    def test_missing_action_comparison_rejected(self):
        """A configuration with an incomplete candidate set is not comparable."""
        rows = [x for x in self.sample() if not (
            x["group"] == "c-2" and x["action"] == "gateway_restrict"
        )]
        with self.assertRaises(ValueError):
            paired_differences(rows, "test")

    def test_unknown_split_rejected(self):
        """Evaluation cannot introduce an unregistered fourth partition."""
        with self.assertRaises(ValueError):
            paired_differences(self.sample(), "unknown")


if __name__ == "__main__":
    unittest.main()
