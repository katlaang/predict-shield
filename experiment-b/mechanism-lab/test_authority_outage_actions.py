import unittest
from pathlib import Path
from unittest.mock import patch

import authority_outage_actions as exp


class OutageActionsTests(unittest.TestCase):
    @patch("authority_outage_actions.request", return_value=(None, {}, 12))
    def test_resync_cannot_succeed_with_authority_stopped(self, request):
        result = exp.apply_action("resync_policy", "x" * 32, Path("."))
        self.assertEqual(result["action_status"], "TRANSPORT_UNAVAILABLE")
        self.assertIsNone(result["action_http_status"])

    @patch("authority_outage_actions.request", return_value=(202, {}, 12))
    def test_resync_unexpectedly_published_fails(self, request):
        with self.assertRaisesRegex(RuntimeError, "became reachable"):
            exp.apply_action("resync_policy", "x" * 32, Path("."))

    @patch("authority_outage_actions.wait_for_target", return_value=2.5)
    @patch("authority_outage_actions.compose_command")
    def test_restart_is_real_docker_operation(self, command, ready):
        result = exp.apply_action("restart_enforcer", "x" * 32, Path("/tmp/lab"))
        command.assert_called_once_with(["restart", "enforcer-b"], cwd=Path("/tmp/lab"))
        self.assertEqual(result["restart_recovery_seconds"], 2.5)

    @patch("authority_outage_actions.request", return_value=(200, {}, 1))
    def test_restricted_gateway_is_not_assumed_to_verify(self, request):
        result = exp.apply_action("gateway_restrict", "x" * 32, Path("."))
        self.assertEqual(result["action_status"], "GATEWAY_RESTRICTION_ACCEPTED")
        self.assertNotIn("verification_status", result)

    @patch("authority_outage_actions.request")
    def test_gateway_samples_count_both_identities(self, request):
        request.side_effect = [(403, {}, 1), (403, {}, 1),
                               (200, {}, 1), (503, {}, 1)]
        report = exp.sample_gateway(count=2)
        self.assertEqual(report["revoked"], {"403": 1, "200": 1})
        self.assertEqual(report["authorized"], {"403": 1, "503": 1})

    def test_no_same_credential_execution(self):
        with self.assertRaises(ValueError):
            exp.execute("x" * 32, "x" * 32, Path("."))


if __name__ == "__main__":
    unittest.main()
