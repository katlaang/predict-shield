"""Read-only metadata contract tests, not a successful defense evaluation."""
import unittest
from authority_revision_observer import authority_revision_gap

NODES = ("enforcer-a","enforcer-b","enforcer-c","enforcer-hidden")


def expectation(now=100., revision=11):
    return {
        "status":"OBSERVED_OPERATOR_METADATA",
        "revision":revision,
        "observed_at_monotonic":now-.1,
        "revocation_state_disclosed":False,
        "oracle_accessed":False,
    }


def nodes(revision=10):
    return [{"node":name,"observed":True,"applied_revision":revision}
            for name in NODES]


class RevisionEvidenceTests(unittest.TestCase):
    def test_all_enforcer_revision_gaps_are_preaction_operational_metadata(self):
        r=authority_revision_gap(expectation(),nodes(),now_monotonic=100.)
        self.assertEqual(r["status"],"OBSERVED_OPERATOR_REVISION_GAP")
        self.assertEqual(set(r["per_node_gap"].values()),{1})
        self.assertFalse(r["verified_policy_outcome"])

    def test_no_fabricated_gap_when_all_current(self):
        r=authority_revision_gap(expectation(),nodes(11),now_monotonic=100.)
        self.assertFalse(r["any_revision_gap"])

    def test_stale_or_missing_revision_is_unknown(self):
        for expectation_data in (None, {"status":"UNKNOWN"}, expectation(now=89.)):
            r=authority_revision_gap(expectation_data,nodes(),now_monotonic=100.)
            self.assertEqual(r["status"],"UNKNOWN")

    def test_privileged_oracle_claim_is_not_metadata(self):
        r=expectation()
        r["revocation_state_disclosed"]=True
        self.assertEqual(authority_revision_gap(r,nodes(),now_monotonic=100.)["status"],"UNKNOWN")

    def test_missing_or_duplicate_node_denies_complete_gap(self):
        wrong=nodes()
        wrong[0]["node"]=wrong[1]["node"]
        self.assertEqual(authority_revision_gap(expectation(),wrong,now_monotonic=100.)["status"],"UNKNOWN")

    def test_local_revision_ahead_of_source_is_not_treated_as_converged(self):
        self.assertEqual(authority_revision_gap(expectation(),nodes(12),now_monotonic=100.)["status"],"UNKNOWN")


if __name__=="__main__":
    unittest.main()
