"""Unit tests for non-oracle operational telemetry used by the AI estimator."""
import unittest

from train import summarize_operator_telemetry, to_features


class OperatorEvidenceTests(unittest.TestCase):
    """Prevent private experimental truth from being mistaken for model input."""

    def test_pre_action_revision_divergence_and_missingness(self):
        """Observed process revisions, failures and missing feeds are summarized."""
        items = [
            {"node": "enforcer-a", "observed": True,
             "applied_revision": 10, "cache_age_ms": 110,
             "handled_events": 4, "refresh_failed": False,
             "scheduled_callbacks_pending": 0},
            {"node": "enforcer-b", "observed": True,
             "applied_revision": 8, "cache_age_ms": 400,
             "handled_events": 2, "refresh_failed": True,
             "scheduled_callbacks_pending": 1},
            {"node": "enforcer-c", "observed": True,
             "applied_revision": 10, "cache_age_ms": 250,
             "handled_events": 4, "refresh_failed": False,
             "scheduled_callbacks_pending": 0},
            {"node": "enforcer-hidden", "observed": False},
        ]
        result = summarize_operator_telemetry(items)
        self.assertEqual(result["operator_missing_count"], 1)
        self.assertEqual(result["operator_revision_spread"], 2)
        self.assertEqual(result["operator_max_cache_age_ms"], 400)
        self.assertEqual(result["operator_refresh_failure_count"], 1)
        self.assertEqual(result["operator_pending_callback_count"], 1)

    def test_injected_fault_label_does_not_change_model_features(self):
        """Adding hidden lab fault metadata cannot directly affect encoding."""
        signals = summarize_operator_telemetry([
            {"observed": True, "applied_revision": 4, "cache_age_ms": 150,
             "handled_events": 2, "refresh_failed": False,
             "scheduled_callbacks_pending": 0}
        ])
        sample = {
            "action": "resync_policy",
            "pre_action": {
                "cache_ttl_ms": 4500, "requested_rps": 35,
                "gateway_visible_enforcer_count": 4,
                "initial_gateway_allowed_fraction": .25,
                "routing_profile": "skewed_a", **signals
            },
            "fault": "loss", "target": "enforcer-hidden",
        }
        baseline = to_features(sample)
        sample["fault"] = "reorder"
        sample["target"] = "enforcer-a"
        self.assertEqual(baseline, to_features(sample))
        sample["pre_action"]["operator_revision_spread"] = 3
        self.assertNotEqual(baseline, to_features(sample))

    def test_absent_telemetry_is_declared_missing(self):
        """No sensor readings must not be encoded as four healthy processes."""
        summary = summarize_operator_telemetry([])
        self.assertEqual(summary["operator_missing_count"], 4)
        self.assertEqual(summary["operator_observed_count"], 0)


if __name__ == "__main__":
    unittest.main()
