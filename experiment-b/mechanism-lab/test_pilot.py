"""Pure Python contract tests for the mechanism-based experiment runner.

These tests require no network, Docker, Kafka, or access to the oracle. They
verify that invalid inputs are rejected without initiating actions and that
the pilot uses an explicit four-action allowlist.
"""
import unittest
from pilot import ACTIONS, measure_under_load, perform_action, request


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


if __name__ == "__main__":
    unittest.main()
