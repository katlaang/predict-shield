"""Focused tests for v3.1 physical consumer-pause pilot orchestration."""
import unittest
from unittest.mock import patch

import v31_consumer_action_pilot as pilot


class V31ConsumerActionTests(unittest.TestCase):
    @patch("v31_consumer_action_pilot.request")
    def test_resume_must_be_physically_observed(self, request):
        request.side_effect = [(200, {}, 1),
                               (200, {"container_paused": False}, 1)]
        pilot.resume_consumer("x" * 32)
        self.assertEqual(request.call_count, 2)

    @patch("v31_consumer_action_pilot.request")
    @patch("v31_consumer_action_pilot.time.monotonic", side_effect=[0.0, 15.0])
    def test_resume_never_assumed_from_acceptance(self, monotonic, request):
        request.side_effect = [(200, {}, 1),
                               (200, {"container_paused": True}, 1)]
        with self.assertRaisesRegex(RuntimeError, "did not physically resume"):
            pilot.resume_consumer("x" * 32)

    @patch("v31_consumer_action_pilot.wait_ready")
    @patch("v31_consumer_action_pilot.resume_consumer")
    @patch("v31_consumer_action_pilot.run_case")
    def test_refuses_unobserved_physical_fault(self, run_case, resume, ready):
        run_case.return_value = {
            "fault_mode": "consumer_paused",
            "before": {"oracle": {"all_revoked_access_denied": True}},
        }
        with self.assertRaisesRegex(RuntimeError, "did not cause initial stale"):
            pilot.execute("c" * 32, "o" * 32)
        self.assertEqual(resume.call_count, 2)

    def test_rejects_same_credentials(self):
        with self.assertRaises(ValueError):
            pilot.execute("a" * 32, "a" * 32)


if __name__ == "__main__":
    unittest.main()
