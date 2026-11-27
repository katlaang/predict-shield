"""Pure Python contract tests for the mechanism-based experiment runner.

These tests require no network, Docker, Kafka, or access to the oracle. They
verify that invalid inputs are rejected without initiating actions and that
the pilot uses an explicit four-action allowlist.
"""
import unittest
from unittest.mock import patch
from pilot import ACTIONS, ENFORCERS, measure_under_load, operator_telemetry, perform_action, request


class MechanismPilotContractTests(unittest.TestCase):
    """Protect the lab-only executor from unsupported control operations."""

    def test_all_four_actions_are_explicit(self):
        """Only the preregistered corrective actions are accepted."""
        self.assertEqual(set(ACTIONS), {
            "resync_policy", "restart_enforcer",
            "gateway_restrict", "monitor_only",
        })

    def test_invalid_destination_rejected_before_network(self):
        """The HTTP helper cannot be redirected to arbitrary remote targets."""
        with self.assertRaises(ValueError):
            request("https://example.com", "/protected")

    def test_unsupported_action_rejected_before_network(self):
        """An unsupported action cannot reach an administrative endpoint."""
        with self.assertRaises(ValueError):
            perform_action("arbitrary_command", "disposable")

    def test_unsafe_load_rejected_before_network(self):
        """The pilot's controlled workload limit applies before any request."""
        with self.assertRaises(ValueError):
            measure_under_load("monitor_only", "disposable",
                               requests_per_second=100000)


    def test_java_v2_telemetry_is_observed_on_all_four_enforcers(self):
        """Actual Java response version must never become four missing nodes."""
        def fake_request(node, path, **kwargs):
            self.assertEqual(path, "/operator/telemetry")
            return 200, {
                "instance": node,
                "observation_type": "operator_pre_action_v2",
                "applied_revision": 3,
                "cache_age_ms": 20,
                "cache_ttl_ms": 3000,
                "legitimate_service_latency_ms": 10,
                "handled_events": 4,
                "refresh_failed": False,
                "scheduled_callbacks_pending": 0,
                "consumer_state_observed": True,
                "consumer_running": True,
                "consumer_paused": False,
                "consumer_pause_requested": False,
                "broker_consumer_lag_measured": False,
            }, 0.01
        with patch("pilot.request", side_effect=fake_request) as request_mock:
            observed = operator_telemetry("synthetic-credential")
        self.assertEqual(request_mock.call_count, len(ENFORCERS))
        self.assertEqual(len(observed), len(ENFORCERS))
        self.assertTrue(all(o["observed"] for o in observed))
        self.assertEqual([o["node"] for o in observed], list(ENFORCERS))
        self.assertTrue(all(o["operator_schema"] == "operator_pre_action_v2" for o in observed))

    def test_misidentified_or_old_telemetry_is_not_treated_as_observed(self):
        cases = ("operator_pre_action", "not-registered")
        for schema in cases:
            with self.subTest(schema=schema):
                def bad_response(node, path, **kwargs):
                    return 200, {
                        "instance": "wrong-enforcer",
                        "observation_type": schema,
                    }, 0.01
                with patch("pilot.request", side_effect=bad_response):
                    rows = operator_telemetry("synthetic-credential")
                self.assertTrue(all(not row["observed"] for row in rows))
                self.assertTrue(all(row["observation_status"] ==
                                    "UNAVAILABLE_OR_SCHEMA_INVALID" for row in rows))

    def test_incomplete_v2_payload_is_rejected_not_imputed(self):
        def incomplete(node, path, **kwargs):
            return 200, {"instance": node, "observation_type": "operator_pre_action_v2",
                         "applied_revision": 3}, 0.01
        with patch("pilot.request", side_effect=incomplete):
            rows = operator_telemetry("synthetic-credential")
        self.assertEqual(sum(row["observed"] for row in rows), 0)


if __name__ == "__main__":
    unittest.main()
