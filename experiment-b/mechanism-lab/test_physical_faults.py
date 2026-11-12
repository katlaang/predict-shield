"""Unit tests for fail-closed physical authority fault smoke harness.

These tests mock Docker and HTTP. They are not proof of physical execution.
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

import physical_faults


class PhysicalAuthorityTests(unittest.TestCase):
    def test_compose_whitelist_rejects_unrelated_service(self):
        with self.assertRaises(ValueError):
            physical_faults.compose_command(["stop", "broker"], cwd=".")

    @patch("physical_faults.subprocess.run")
    def test_compose_uses_explicit_operations(self, run):
        run.return_value.returncode = 0
        physical_faults.compose_command(["stop", "authority"], cwd="/tmp/lab")
        run.assert_called_once()
        args = run.call_args.args[0]
        self.assertEqual(args, ["docker", "compose", "stop", "authority"])

    @patch("physical_faults.wait_ready")
    @patch("physical_faults.wait_for_target", return_value=1.5)
    @patch("physical_faults.compose_command")
    @patch("physical_faults.request")
    def test_outage_rejects_false_recovery_and_restores_authority(
            self, request, compose, ready_target, ready):
        request.side_effect = [(200, {}, 1), (None, {}, 1),
                               (None, {}, 1), (200, {}, 1)]
        # wait_authority_unavailable sees None, resync sees None,
        # after restart sees 200: false recovery must stop the test.
        with self.assertRaisesRegex(RuntimeError, "unexpectedly recovered"):
            physical_faults.run_outage("a" * 32, compose_dir="/tmp/lab")
        self.assertEqual(compose.call_args_list[-1],
                         call(["start", "authority"], cwd="/tmp/lab"))
        self.assertEqual(ready.call_count, 2)

    @patch("physical_faults.wait_ready")
    @patch("physical_faults.wait_for_target", return_value=1.5)
    @patch("physical_faults.compose_command")
    @patch("physical_faults.request")
    def test_realistic_outage_signal_required(self, request, compose, target, ready):
        request.side_effect = [(200, {}, 1), (None, {}, 1),
                               (None, {"error": "upstream unreachable"}, 1),
                               (None, {}, 1)]
        result = physical_faults.run_outage("a" * 32, compose_dir="/tmp/lab")
        self.assertEqual(result["outcome"], "MECHANISM_CONSTRAINT_OBSERVED")
        self.assertTrue(result["resync_unavailable"])
        self.assertTrue(result["authority_still_unavailable"])
        self.assertEqual(compose.call_args_list[-1],
                         call(["start", "authority"], cwd="/tmp/lab"))


if __name__ == "__main__":
    unittest.main()
