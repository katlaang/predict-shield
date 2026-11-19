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

    def test_real_dual_probe_contract_uses_all_four_nodes_and_both_principals(self):
        from python.offline_authority_witness import freeze_witness
        witness = freeze_witness(
            {"trialId": "lab-case-1", "revoked": True},
            authority_http=200, inventory=list(exp.ENFORCERS),
            captured_at="2026-11-19T00:00:00Z",
        )
        calls = []
        def observed(node, path, *, timeout, authorized_lab_user=False):
            calls.append((node, path, authorized_lab_user))
            return (200 if authorized_lab_user else 403, {}, 0.5)
        result = exp.collect_dual_principal_probes(
            observed, witness=witness, authority_http=None,
            observed_at="2026-11-19T00:00:30Z",
        )
        self.assertEqual(len(calls), 8)
        self.assertEqual({n for n, _, _ in calls}, set(exp.ENFORCERS))
        self.assertTrue(all(path == "/protected" for _, path, _ in calls))
        self.assertEqual(sum(a for _, _, a in calls), 4)
        self.assertEqual(result["revoked_denial_fraction_bounds"], [1, 1])
        self.assertEqual(result["legitimate_access_fraction_bounds"], [1, 1])
        self.assertEqual(result["verification_outcome"], "INDETERMINATE")
        self.assertIsNone(result["authority_truth_current"])

    def test_unreachable_probes_remain_unknown_not_success(self):
        from python.offline_authority_witness import freeze_witness
        witness = freeze_witness(
            {"trialId": "lab-case-1", "revoked": True},
            authority_http=200, inventory=list(exp.ENFORCERS),
            captured_at="2026-11-19T00:00:00Z",
        )
        def observed(node, path, *, timeout, authorized_lab_user=False):
            if node == exp.ENFORCERS[0]:
                return None, {"error": "unreachable"}, 20.0
            return (200 if authorized_lab_user else 403, {}, 0.5)
        result = exp.collect_dual_principal_probes(
            observed, witness=witness, authority_http=None,
            observed_at="2026-11-19T00:00:30Z",
        )
        self.assertEqual(result["revoked_denial_fraction_bounds"], [0.75, 1.0])
        self.assertEqual(result["legitimate_access_fraction_bounds"], [0.75, 1.0])
        self.assertEqual(result["verification_outcome"], "INDETERMINATE")

    def test_live_authority_cannot_be_scored_as_offline(self):
        from python.offline_authority_witness import freeze_witness
        witness = freeze_witness(
            {"trialId": "lab-case-1", "revoked": True},
            authority_http=200, inventory=list(exp.ENFORCERS),
            captured_at="2026-11-19T00:00:00Z",
        )
        with self.assertRaises(ValueError):
            exp.collect_dual_principal_probes(
                lambda *args, **kwargs: (403, {}, 0.5),
                witness=witness, authority_http=200,
                observed_at="2026-11-19T00:00:30Z",
            )

    def test_no_same_credential_execution(self):
        with self.assertRaises(ValueError):
            exp.execute("x" * 32, "x" * 32, Path("."))


if __name__ == "__main__":
    unittest.main()
