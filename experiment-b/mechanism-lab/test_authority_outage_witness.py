"""Tests for fail-closed authority-outage witness and uncertainty bounds."""
import unittest
from datetime import datetime, timezone
from dataclasses import replace

from authority_outage_witness import capture_witness, observe_offline


def before():
    return {
        "authority_http": 200, "authority_truth_available": True,
        "authority": {"trialId": "test-trial-123", "revision": 3, "revoked": True},
        "expected_inventory_count": 4,
        "targets": [{"node": x} for x in ("a", "b", "c", "hidden")],
    }


def after(statuses=(403, 403, 200, None)):
    return {
        "authority_http": None, "authority_truth_available": False,
        "inventory_complete": False, "all_revoked_access_denied": None,
        "targets": [
            {"node": node, "direct_probe_http": status,
             "admin_http": 200, "admin": {"trial_id": "test-trial-123", "revoked": True}}
            for node, status in zip(("a", "b", "c", "hidden"), statuses)
        ],
    }


class WitnessTests(unittest.TestCase):
    def witness(self):
        return capture_witness(before(), observed_at=datetime(2026, 11, 14, tzinfo=timezone.utc))

    def test_provenance_and_partial_observation_bounds(self):
        w = self.witness()
        r = observe_offline(after(), w)
        self.assertEqual(len(w.commitment_sha256), 64)
        self.assertEqual((r["observed_allow_count"], r["observed_deny_count"],
                          r["unknown_target_count"]), (1, 2, 1))
        self.assertEqual(r["observed_allow_fraction_lower_bound"], 0.25)
        self.assertEqual(r["observed_allow_fraction_upper_bound"], 0.50)
        self.assertEqual(r["verification_status"], "INDETERMINATE")

    def test_all_denied_still_cannot_verify_offline_authority(self):
        r = observe_offline(after((403, 403, 403, 403)), self.witness())
        self.assertEqual(r["observed_allow_fraction_upper_bound"], 0.0)
        self.assertEqual(r["authority_truth_status"], "UNKNOWN")
        self.assertNotEqual(r["verification_status"], "VERIFIED")

    def test_live_or_fabricated_policy_triggers_rejection(self):
        post = after()
        post["all_revoked_access_denied"] = True
        with self.assertRaisesRegex(ValueError, "UNKNOWN"):
            observe_offline(post, self.witness())

    def test_stale_trial_is_unknown_not_denied(self):
        post = after((403, 403, 403, 403))
        post["targets"][0]["admin"]["trial_id"] = "earlier-trial"
        r = observe_offline(post, self.witness())
        self.assertEqual(r["unknown_target_count"], 1)
        self.assertEqual(r["observed_allow_fraction_upper_bound"], 0.25)

    def test_offline_targets_must_match_exact_pre_outage_inventory(self):
        post = after((403, 403, 403, 403))
        post["targets"][3]["node"] = "unexpected-enforcer"
        with self.assertRaisesRegex(ValueError, "frozen pre-outage witness"):
            observe_offline(post, self.witness())

    def test_forged_or_modified_witness_cannot_be_admitted(self):
        witness = self.witness()
        tampered = replace(witness, trial_id="different-trial")
        with self.assertRaisesRegex(ValueError, "witness commitment"):
            observe_offline(after(), tampered)
        reordered = replace(witness, expected_nodes=tuple(reversed(witness.expected_nodes)))
        with self.assertRaisesRegex(ValueError, "witness commitment"):
            observe_offline(after(), reordered)

    def test_denial_from_allowed_policy_is_unknown_not_verified_denial(self):
        post = after((403, 403, 403, 403))
        post["targets"][0]["admin"]["revoked"] = False
        result = observe_offline(post, self.witness())
        self.assertEqual(result["observed_deny_count"], 3)
        self.assertEqual(result["unknown_target_count"], 1)
        self.assertEqual(result["observed_allow_fraction_upper_bound"], 0.25)
        self.assertEqual(result["verification_status"], "INDETERMINATE")

    def test_immutable_witness_includes_exact_inventory(self):
        witness = self.witness()
        self.assertEqual(witness.expected_nodes, ("a", "b", "c", "hidden"))
        result = observe_offline(after(), witness)
        self.assertEqual(result["schema"], "predict-shield/authority-outage-observation/2")
        self.assertTrue(result["witness_inventory_identical_to_pre_outage"])

    def test_capture_rejects_duplicate_or_nonstring_target_id(self):
        snapshot = before()
        snapshot["targets"][3]["node"] = "a"
        with self.assertRaisesRegex(ValueError, "distinct physical"):
            capture_witness(snapshot, observed_at=datetime.now(timezone.utc))
        snapshot = before()
        snapshot["targets"][0]["node"] = ["not-a-real-id"]
        with self.assertRaisesRegex(ValueError, "four-node"):
            capture_witness(snapshot, observed_at=datetime.now(timezone.utc))

    def test_no_witness_when_authority_offline_or_not_revoked(self):
        a = before()
        a["authority_http"] = None
        with self.assertRaises(ValueError):
            capture_witness(a, observed_at=datetime.now(timezone.utc))
        b = before()
        b["authority"]["revoked"] = False
        with self.assertRaises(ValueError):
            capture_witness(b, observed_at=datetime.now(timezone.utc))

    def test_rejects_missing_inventory_and_naive_timestamp(self):
        b = before()
        b["targets"].pop()
        with self.assertRaisesRegex(ValueError, "four-node"):
            capture_witness(b, observed_at=datetime.now(timezone.utc))
        with self.assertRaises(ValueError):
            capture_witness(before(), observed_at=datetime(2026, 11, 14))


if __name__ == "__main__":
    unittest.main()
