"""No-network checks for separate operator-only v2 collector.

The locked v3.1 experiment collector remains unchanged.
"""
import unittest
from unittest.mock import patch

from operator_telemetry_v2 import operator_telemetry_v2
from pilot import ENFORCERS


def payload(name, *, paused=False):
    return {
        "instance": name,
        "observation_type": "operator_pre_action_v2",
        "observed_at_epoch_ms": 1764200000000,
        "applied_revision": 2,
        "cache_age_ms": 500,
        "cache_ttl_ms": 30000,
        "legitimate_service_latency_ms": 15,
        "handled_events": 4,
        "refresh_failed": False,
        "scheduled_callbacks_pending": 0,
        "consumer_state_observed": True,
        "consumer_running": True,
        "consumer_paused": paused,
        "consumer_pause_requested": paused,
        "fault_mode": "SHOULD_NOT_LEAK",
        "revoked": True,
    }


class OperatorV2CollectionTests(unittest.TestCase):
    def test_only_operator_endpoint_and_allowed_signals_propagate(self):
        def stub(node, path, *, token, timeout):
            self.assertEqual(path, "/operator/telemetry")
            self.assertEqual(token, "a" * 32)
            return 200, payload(node, paused=node == "enforcer-b"), .01
        with patch("operator_telemetry_v2.request", side_effect=stub) as request:
            rows = operator_telemetry_v2("a" * 32)
        self.assertEqual(request.call_count, len(ENFORCERS))
        self.assertEqual(len(rows), 4)
        self.assertTrue(rows[1]["consumer_paused"])
        self.assertFalse(rows[0]["consumer_paused"])
        self.assertTrue(all(r["observed"] for r in rows))
        self.assertFalse(any("fault_mode" in r or "revoked" in r for r in rows))
        self.assertFalse(any(r["broker_consumer_lag_measured"] for r in rows))

    def test_misidentified_response_is_missing_not_healthy(self):
        def stub(node, path, *, token, timeout):
            wrong = "enforcer-a" if node == "enforcer-b" else node
            return 200, payload(wrong), 0.1
        with patch("operator_telemetry_v2.request", side_effect=stub):
            rows = operator_telemetry_v2("a" * 32)
        self.assertFalse(rows[1]["observed"])
        self.assertFalse(rows[1]["consumer_state_observed"])
        self.assertNotIn("consumer_running", rows[1])

    def test_old_schema_cannot_be_accepted_as_new_listener_health(self):
        def stub(node, path, *, token, timeout):
            r = payload(node)
            r["observation_type"] = "operator_pre_action"
            return 200, r, 0.01
        with patch("operator_telemetry_v2.request", side_effect=stub):
            rows = operator_telemetry_v2("a" * 32)
        self.assertTrue(all(x["observed"] is False for x in rows))

    def test_no_credential_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "credential"):
            operator_telemetry_v2("short")


if __name__ == "__main__":
    unittest.main()
