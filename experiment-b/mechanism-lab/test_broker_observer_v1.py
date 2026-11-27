"""Unit-only provenance/offset checks; no simulated data as experiment results."""
import copy
import unittest
from broker_observer_v1 import GROUPS, verify_broker_evidence


def valid_broker(now=100.0, *, lag=0):
    return {
        "schema": "predict-shield/broker-offset-witness/1",
        "status": "MEASURED",
        "observation_type": "kafka_admin_readonly",
        "topic": "lab-policy",
        "atomic_snapshot": False,
        "payload_contents_read": False,
        "security_outcome_verified": False,
        "group_membership_observed": False,
        "observed_at_monotonic": now-0.1,
        "request_elapsed_seconds": .5,
        "groups": {
            name: {
                "status": "MEASURED",
                "consumer_group": name,
                "total_committed_backlog": lag if name == "enforcer-b" else 0,
                "partitions": [{
                    "partition": 0, "committed_offset": 10 - (lag if name == "enforcer-b" else 0),
                    "log_end_offset": 10, "committed_backlog": lag if name == "enforcer-b" else 0,
                }],
            } for name in GROUPS
        },
    }


class BrokerEvidenceTests(unittest.TestCase):
    def test_positive_committed_backlog_is_not_proof_of_failed_defense(self):
        result = verify_broker_evidence(valid_broker(lag=3), now_monotonic=100.)
        self.assertEqual(result["status"], "MEASURED")
        self.assertEqual(result["backlog"]["enforcer-b"], 3)
        self.assertFalse(result["evidence_of_security_resolution"])
        self.assertFalse(result["consumer_processing_correctness_verified"])

    def test_zero_backlog_is_not_oracle_truth(self):
        result = verify_broker_evidence(valid_broker(), now_monotonic=100.)
        self.assertEqual(result["status"], "MEASURED")
        self.assertEqual(sum(result["backlog"].values()), 0)
        self.assertFalse(result["evidence_of_security_resolution"])

    def test_missing_group_must_not_be_zero(self):
        bad = valid_broker()
        bad["groups"].pop("enforcer-hidden")
        result = verify_broker_evidence(bad, now_monotonic=100.)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["backlog"], {})

    def test_missing_commit_and_misreported_math_rejected(self):
        bad = valid_broker(lag=3)
        bad["groups"]["enforcer-b"]["partitions"][0]["committed_offset"] = 10
        result = verify_broker_evidence(bad, now_monotonic=100.)
        self.assertIn("INCONSISTENT_PARTITION_OFFSETS", result["reasons"])

    def test_corrupt_duplicate_partition_rejected(self):
        bad = valid_broker()
        bad["groups"]["enforcer-b"]["partitions"].append(
            copy.deepcopy(bad["groups"]["enforcer-b"]["partitions"][0]))
        result = verify_broker_evidence(bad, now_monotonic=100.)
        self.assertEqual(result["status"], "UNKNOWN")

    def test_stale_future_and_missing_timestamps_fail_closed(self):
        for value in (None, 98., 111.):
            bad = valid_broker()
            bad["observed_at_monotonic"] = value
            self.assertIn("STALE_OR_INVALID_BROKER_TIMESTAMP",
                          verify_broker_evidence(bad, now_monotonic=110.)["reasons"])

    def test_unknown_is_not_zero(self):
        result = verify_broker_evidence({"schema":"predict-shield/broker-offset-witness/1",
                                         "status":"UNKNOWN"}, now_monotonic=100.)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertNotEqual(result["backlog"], {g: 0 for g in GROUPS})

    def test_observer_cannot_call_itself_atomic(self):
        bad = valid_broker()
        bad["atomic_snapshot"] = True
        self.assertIn("INCONSISTENT_BROKER_SCOPE_CLAIMS",
                      verify_broker_evidence(bad, now_monotonic=100.)["reasons"])

    def test_missing_remote_evidence(self):
        self.assertEqual(verify_broker_evidence(None, now_monotonic=100.)["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
