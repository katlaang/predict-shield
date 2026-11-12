"""Unit tests for sampled, independently observed exposure-seconds.

All sample arrays are unit-test fixtures. They are not measured Kafka-lab
outcomes and must never be used as scientific training data.
"""
import unittest

from pilot import integrate_gateway_exposure


class TimedGatewayExposureTests(unittest.TestCase):
    """Require time integration to preserve exposure and unknown intervals."""

    def test_integrated_exposure_differs_from_final_state(self):
        """One second of allowed access must remain visible after final denial."""
        timeline = integrate_gateway_exposure([
            {"seconds_after_start": 0.0, "http_status": 200},
            {"seconds_after_start": 1.0, "http_status": 403},
            {"seconds_after_start": 3.0, "http_status": 403},
        ], window_seconds=4.0)
        self.assertAlmostEqual(timeline["exposure_seconds_lower_bound"], 1.0)
        self.assertAlmostEqual(timeline["exposure_fraction_lower_bound"], .25)
        self.assertAlmostEqual(timeline["unknown_seconds"], 0.0)

    def test_transport_failure_is_unknown_not_denial(self):
        """Missing or failed probes must increase the upper exposure bound."""
        timeline = integrate_gateway_exposure([
            {"seconds_after_start": 0.5, "http_status": 403},
            {"seconds_after_start": 1.5, "http_status": 502},
            {"seconds_after_start": 3.5, "http_status": 403},
        ], window_seconds=4.0)
        self.assertAlmostEqual(timeline["exposure_seconds_lower_bound"], 0.0)
        self.assertAlmostEqual(timeline["unknown_seconds"], 2.5)
        self.assertAlmostEqual(timeline["exposure_seconds_upper_bound"], 2.5)

    def test_insufficient_valid_observations_refuse_label(self):
        """One successful probe is not an adequate timeline."""
        with self.assertRaises(ValueError):
            integrate_gateway_exposure([
                {"seconds_after_start": .1, "http_status": 403},
                {"seconds_after_start": .2, "http_status": 503},
            ], window_seconds=4.0)

    def test_out_of_window_timestamp_refused(self):
        """Late results cannot silently extend the preregistered interval."""
        with self.assertRaises(ValueError):
            integrate_gateway_exposure([
                {"seconds_after_start": .1, "http_status": 200},
                {"seconds_after_start": 4.1, "http_status": 403},
            ], window_seconds=4.0)


if __name__ == "__main__":
    unittest.main()
