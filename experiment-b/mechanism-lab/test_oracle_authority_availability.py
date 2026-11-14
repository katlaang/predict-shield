"""Oracle-truth separation tests for physically unavailable authority."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "python"))
import oracle as oracle_module


def responses(authority_online: bool):
    policy = (200, {"revoked": True, "revision": 8, "trialId": "trial-123"}) if authority_online else (
        None, {"error": "unreachable"})
    sequence = [policy]
    for _ in range(4):
        sequence.extend([
            (403, {"allowed": False}),
            (200, {"revoked": True, "trial_id": "trial-123", "revision": 8}),
        ])
    return sequence


class AuthorityTruthAvailabilityTests(unittest.TestCase):
    @patch.object(oracle_module, "NODES", ("http://a", "http://b", "http://c", "http://hidden"))
    @patch.object(oracle_module, "request_json")
    def test_fully_denying_targets_do_not_certify_offline_authority(self, request):
        request.side_effect = responses(False)
        result = oracle_module.observe()
        self.assertFalse(result["authority_truth_available"])
        self.assertTrue(result["direct_target_observations_complete"])
        self.assertFalse(result["inventory_complete"])
        self.assertIsNone(result["all_revoked_access_denied"])
        self.assertTrue(result["target_observations_are_not_policy_truth"])
        self.assertEqual(len(result["targets"]), 4)

    @patch.object(oracle_module, "NODES", ("http://a", "http://b", "http://c", "http://hidden"))
    @patch.object(oracle_module, "request_json")
    def test_live_policy_and_independent_targets_can_confirm_deny(self, request):
        request.side_effect = responses(True)
        result = oracle_module.observe()
        self.assertTrue(result["authority_truth_available"])
        self.assertTrue(result["direct_target_observations_complete"])
        self.assertTrue(result["inventory_complete"])
        self.assertTrue(result["all_revoked_access_denied"])

    @patch.object(oracle_module, "NODES", ("http://a", "http://b", "http://c", "http://hidden"))
    @patch.object(oracle_module, "request_json")
    def test_missing_target_cannot_certify_even_with_live_authority(self, request):
        replies = responses(True)
        replies[1] = (None, {"error": "timeout"})
        request.side_effect = replies
        result = oracle_module.observe()
        self.assertTrue(result["authority_truth_available"])
        self.assertFalse(result["direct_target_observations_complete"])
        self.assertFalse(result["inventory_complete"])
        self.assertIsNone(result["all_revoked_access_denied"])


if __name__ == "__main__":
    unittest.main()
