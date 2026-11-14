import unittest
from pathlib import Path
from unittest.mock import patch

from outage_timed_measure import summarize_samples, observe_during_action


class OutageTimedMeasurementTests(unittest.TestCase):
    def test_interval_bounds_and_real_failure_denominators(self):
        rows = [
            {"principal": "revoked", "seconds_after_start": 0.5, "http_status": 200},
            {"principal": "authorized", "seconds_after_start": 0.6, "http_status": 200},
            {"principal": "legitimate", "seconds_after_start": 0.7, "http_status": 503},
            {"principal": "revoked", "seconds_after_start": 1.5, "http_status": None},
            {"principal": "authorized", "seconds_after_start": 1.6, "http_status": 403},
            {"principal": "legitimate", "seconds_after_start": 1.7, "http_status": 200},
            {"principal": "revoked", "seconds_after_start": 2.5, "http_status": 403},
        ]
        result = summarize_samples(rows, window_seconds=3)
        exposure = result["revoked_gateway_exposure"]
        self.assertAlmostEqual(exposure["exposure_seconds_lower_bound"], 1)
        self.assertAlmostEqual(exposure["exposure_seconds_upper_bound"], 2.5)
        self.assertEqual(result["authorized_protected"]["non_200_requests"], 1)
        self.assertEqual(result["legitimate_endpoint"]["non_200_requests"], 1)
        self.assertEqual(result["legitimate_endpoint"]["requests"], 2)
        self.assertEqual(result["policy_verification_from_this_measurement"], "NOT_EVALUATED")

    def test_unknown_cannot_be_silently_scored_as_denied(self):
        rows = [
            {"principal": "revoked", "seconds_after_start": 0.1, "http_status": None},
            {"principal": "authorized", "seconds_after_start": 0.2, "http_status": 200},
            {"principal": "legitimate", "seconds_after_start": 0.3, "http_status": 200},
            {"principal": "revoked", "seconds_after_start": 1.0, "http_status": 403},
            {"principal": "revoked", "seconds_after_start": 1.5, "http_status": 403},
        ]
        result = summarize_samples(rows, window_seconds=2)
        bounds = result["revoked_gateway_exposure"]
        self.assertEqual(bounds["exposure_seconds_lower_bound"], 0)
        self.assertGreater(bounds["exposure_seconds_upper_bound"], 0)

    def test_missing_principal_rejected(self):
        rows = [
            {"principal": "revoked", "seconds_after_start": 0.1, "http_status": 403},
            {"principal": "revoked", "seconds_after_start": 1, "http_status": 403},
            {"principal": "authorized", "seconds_after_start": 0.3, "http_status": 200},
        ]
        with self.assertRaisesRegex(ValueError, "three observer categories"):
            summarize_samples(rows, window_seconds=3)

    def test_no_physical_action_without_environment(self):
        with self.assertRaises(ValueError):
            observe_during_action("monitor_only", "token", Path("."), lambda *a: None,
                                  window_seconds=1)


if __name__ == "__main__":
    unittest.main()
