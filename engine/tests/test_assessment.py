import unittest
from datetime import datetime, timedelta, timezone
from predict_shield.assessment import Evidence, Outcome, assess

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)
def ev(result, source="probe", independent=True, age=0, asset="service-a", assertion="access revoked"):
    return Evidence(asset, assertion, result, NOW - timedelta(seconds=age), source, independent)

class AssessmentTests(unittest.TestCase):
    def run_assessment(self, evidence, **kw):
        return assess("service-a", "access revoked", evidence, now=NOW, **kw)

    def test_verified_requires_independent_positive(self):
        self.assertEqual(self.run_assessment([ev(True)]).outcome, Outcome.VERIFIED)

    def test_missing_evidence_abstains(self):
        self.assertEqual(self.run_assessment([]).outcome, Outcome.INDETERMINATE)

    def test_untrusted_report_not_verified(self):
        self.assertEqual(self.run_assessment([ev(True, independent=False)]).outcome, Outcome.INDETERMINATE)

    def test_stale_evidence_abstains(self):
        self.assertEqual(self.run_assessment([ev(True, age=7200)]).outcome, Outcome.INDETERMINATE)

    def test_independent_failure(self):
        self.assertEqual(self.run_assessment([ev(False)]).outcome, Outcome.NOT_VERIFIED)

    def test_conflict_remains_indeterminate(self):
        result = self.run_assessment([ev(True, source="probe"), ev(False, source="scanner", independent=False)])
        self.assertEqual(result.outcome, Outcome.INDETERMINATE)
        self.assertTrue(result.conflicting_evidence)

    def test_authoritative_failure_overrides_positive_self_report(self):
        evidence = [
            ev(True, source="executor", independent=False),
            ev(False, source="external-deny-probe", independent=True),
        ]
        result = self.run_assessment(evidence)
        self.assertEqual(result.outcome, Outcome.NOT_VERIFIED)
        self.assertTrue(result.conflicting_evidence)

    def test_authoritative_failure_overrides_other_independent_positive(self):
        evidence = [
            ev(True, source="external-probe-a", independent=True),
            ev(False, source="external-probe-b", independent=True),
        ]
        result = self.run_assessment(evidence)
        self.assertEqual(result.outcome, Outcome.NOT_VERIFIED)
        self.assertTrue(result.conflicting_evidence)

    def test_wrong_scope_does_not_count(self):
        self.assertEqual(self.run_assessment([ev(True, asset="service-b")]).outcome, Outcome.INDETERMINATE)

    def test_not_applicable_requires_explicit_flag(self):
        self.assertEqual(self.run_assessment([], applicable=False).outcome, Outcome.NOT_APPLICABLE)

    def test_future_observation_does_not_count(self):
        self.assertEqual(self.run_assessment([ev(True, age=-10)]).outcome, Outcome.INDETERMINATE)

    def test_independent_sources_required(self):
        self.assertEqual(self.run_assessment([ev(True)], required_independent_checks=2).outcome, Outcome.INDETERMINATE)

if __name__ == "__main__":
    unittest.main()
