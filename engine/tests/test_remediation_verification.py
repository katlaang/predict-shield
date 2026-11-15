import unittest
from datetime import datetime, timezone

from predict_shield.assessment import Evidence
from predict_shield.remediation_verification import (
    DEPENDENCY_RESOLUTION_OK,
    NO_NEW_KNOWN_VULNERABILITY,
    NO_REGRESSION,
    VULNERABILITY_RESOLVED,
    evaluate,
)

NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)

SCOPE = {
    VULNERABILITY_RESOLVED: ("example-isp.test", "cve-reproduced:CVE-2026-00001"),
    NO_REGRESSION: ("widget-api", "no_regression:widget-api"),
    NO_NEW_KNOWN_VULNERABILITY: ("left-pad@2.3.0", "no_known_vulnerability_in_new_version"),
    DEPENDENCY_RESOLUTION_OK: ("widget-api", "dependency_resolution_ok:widget-api"),
}


def passing_evidence_for(scope):
    return [
        Evidence(asset=asset, assertion=assertion, observed_pass=True, observed_at=NOW,
                source="fake-check:" + name, independent=True)
        for name, (asset, assertion) in scope.items()
    ]


class RemediationVerificationTests(unittest.TestCase):
    def test_all_four_assertions_verified_is_accepted(self):
        verdict = evaluate(SCOPE, passing_evidence_for(SCOPE), now=NOW)
        self.assertTrue(verdict.accepted)
        self.assertEqual(verdict.blocking_reasons, ())

    def test_a_single_failing_assertion_blocks_acceptance(self):
        evidence = passing_evidence_for(SCOPE)
        asset, assertion = SCOPE[NO_REGRESSION]
        evidence.append(Evidence(asset=asset, assertion=assertion, observed_pass=False,
                                 observed_at=NOW, source="regression-check", independent=True))
        verdict = evaluate(SCOPE, evidence, now=NOW)
        self.assertFalse(verdict.accepted)
        self.assertEqual(len(verdict.blocking_reasons), 1)
        self.assertIn(NO_REGRESSION, verdict.blocking_reasons[0])

    def test_missing_evidence_for_an_assertion_blocks_acceptance_as_indeterminate(self):
        scope_with_no_evidence = dict(SCOPE)
        evidence = [e for e in passing_evidence_for(SCOPE)
                    if e.assertion != SCOPE[DEPENDENCY_RESOLUTION_OK][1]]
        verdict = evaluate(scope_with_no_evidence, evidence, now=NOW)
        self.assertFalse(verdict.accepted)
        self.assertIn("INDETERMINATE", verdict.blocking_reasons[0])

    def test_missing_scope_entry_is_a_caller_error(self):
        incomplete_scope = {k: v for k, v in SCOPE.items() if k != NO_REGRESSION}
        with self.assertRaises(ValueError):
            evaluate(incomplete_scope, passing_evidence_for(SCOPE), now=NOW)

    def test_each_assertion_is_scoped_independently(self):
        # Evidence for one assertion's (asset, assertion) pair must never leak
        # into another assertion's assessment just because it is in the same list.
        evidence = passing_evidence_for(SCOPE)
        verdict = evaluate(SCOPE, evidence, now=NOW)
        for name in SCOPE:
            asset, assertion = SCOPE[name]
            self.assertTrue(
                any(asset == e.asset and assertion == e.assertion for e in evidence)
            )


if __name__=="__main__": unittest.main()
