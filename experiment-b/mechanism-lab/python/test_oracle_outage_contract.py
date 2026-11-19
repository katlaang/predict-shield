"""Regression tests for the independent authority/outage oracle's fail-closed contract.

These are isolated contract tests with mocked transport, NOT evidence of a
physical authority-outage trial or measured decision utility (issue #36).
Run from this directory with: python -m unittest -v test_oracle_outage_contract
"""
import unittest
from unittest.mock import patch

import oracle


NODES = ("http://enforcer-a:8080", "http://enforcer-b:8080")


def observations(*, authority_up=True, revoked=True, first_probe=403,
                 second_probe=403, first_admin_up=True, trial_match=True):
    trial = "frozen-trial-001"
    replies = {
        "http://policy:8080/oracle/policy": (
            (200, {"revoked": revoked, "trialId": trial})
            if authority_up else (None, {"error": "unreachable"})
        ),
    }
    for index, node in enumerate(NODES):
        probe = first_probe if index == 0 else second_probe
        replies[node + "/protected"] = (
            probe, {"message": "observed response"} if probe is not None
            else {"error": "unreachable"}
        )
        admin_up = first_admin_up if index == 0 else True
        replies[node + "/admin/state"] = (
            (200, {"revoked": revoked, "trial_id": (
                "old-trial" if index == 0 and not trial_match else trial
            )}) if admin_up else (None, {"error": "unreachable"})
        )
    return replies


class AuthorityOutageOracleContract(unittest.TestCase):
    def inspect(self, replies):
        def transport(url, *_args, **_kwargs):
            return replies[url]
        with patch.object(oracle, "NODES", NODES), \
             patch.object(oracle, "AUTHORITY", "http://policy:8080"), \
             patch.object(oracle, "request_json", side_effect=transport):
            return oracle.observe()

    def test_healthy_revocation_needs_both_direct_denials(self):
        result = self.inspect(observations())
        self.assertTrue(result["inventory_complete"])
        self.assertTrue(result["authority_truth_available"])
        self.assertIs(result["all_revoked_access_denied"], True)

    def test_one_direct_allow_proves_revocation_not_fully_enforced(self):
        result = self.inspect(observations(first_probe=200))
        self.assertTrue(result["inventory_complete"])
        self.assertIs(result["all_revoked_access_denied"], False)

    def test_authority_outage_never_converts_target_denials_into_policy_truth(self):
        result = self.inspect(observations(authority_up=False))
        self.assertFalse(result["inventory_complete"])
        self.assertFalse(result["authority_truth_available"])
        self.assertTrue(result["direct_target_observations_complete"])
        self.assertTrue(result["target_observations_are_not_policy_truth"])
        self.assertIsNone(result["all_revoked_access_denied"])

    def test_missing_target_does_not_shrink_expected_inventory(self):
        result = self.inspect(observations(first_probe=None))
        self.assertEqual(result["expected_inventory_count"], 2)
        self.assertEqual(len(result["targets"]), 2)
        self.assertFalse(result["inventory_complete"])
        self.assertIsNone(result["all_revoked_access_denied"])

    def test_unreachable_admin_state_does_not_create_a_clean_verdict(self):
        result = self.inspect(observations(first_admin_up=False))
        self.assertFalse(result["inventory_complete"])
        self.assertFalse(result["direct_target_observations_complete"])
        self.assertIsNone(result["all_revoked_access_denied"])

    def test_stale_trial_id_invalidates_complete_policy_snapshot(self):
        result = self.inspect(observations(trial_match=False))
        self.assertFalse(result["inventory_complete"])
        self.assertIsNone(result["all_revoked_access_denied"])

    def test_non_revocation_is_not_misreported_as_revoked_access_denied(self):
        result = self.inspect(observations(revoked=False,
                                            first_probe=200, second_probe=200))
        self.assertTrue(result["inventory_complete"])
        self.assertIsNone(result["all_revoked_access_denied"])


if __name__ == "__main__":
    unittest.main()
