import unittest
from datetime import datetime, timedelta, timezone

from predict_shield.assessment import Evidence
from predict_shield.sast_findings import (
    FINDING_CONFIRMED_BEFORE_FIX,
    FINDING_RESOLVED,
    NO_NEW_HIGH_SEVERITY_FINDING,
    NO_REGRESSION,
    RegisteredScanner,
    ScanFinding,
    confirm_before_fix,
    confirm_no_new_high_severity,
    confirm_resolution,
    evaluate_fix,
)

NOW = datetime(2026, 11, 15, 19, 0, tzinfo=timezone.utc)

REGISTRY = {
    "semgrep-ci": RegisteredScanner(scanner_id="semgrep-ci", name="Semgrep", version="1.90.0", trusted=True),
    "unpinned-tool": RegisteredScanner(scanner_id="unpinned-tool", name="Unreviewed", version="", trusted=True),
    "unreviewed-scanner": RegisteredScanner(scanner_id="unreviewed-scanner", name="Unreviewed", version="2.0", trusted=False),
}


def finding(**overrides):
    base = dict(finding_id="f-0001", asset="billing-api", scanner_id="semgrep-ci",
               rule_id="python.sqli.raw-query", fingerprint="abc123fingerprint",
               file_path="billing/views.py", severity="high", present=True,
               observed_at=NOW - timedelta(minutes=2))
    base.update(overrides)
    return ScanFinding(**base)


class AdmissionCommonTests(unittest.TestCase):
    """Checks shared by both confirm_before_fix and confirm_resolution."""

    def test_unregistered_scanner_is_rejected(self):
        with self.assertRaises(ValueError):
            confirm_before_fix(finding(scanner_id="unknown-tool"), REGISTRY, now=NOW)

    def test_untrusted_registered_scanner_is_rejected(self):
        with self.assertRaises(ValueError):
            confirm_before_fix(finding(scanner_id="unreviewed-scanner"), REGISTRY, now=NOW)

    def test_unpinned_scanner_is_rejected(self):
        with self.assertRaises(ValueError):
            confirm_before_fix(finding(scanner_id="unpinned-tool"), REGISTRY, now=NOW)

    def test_missing_fingerprint_is_rejected(self):
        with self.assertRaises(ValueError):
            confirm_before_fix(finding(fingerprint=""), REGISTRY, now=NOW)

    def test_missing_rule_id_is_rejected(self):
        with self.assertRaises(ValueError):
            confirm_before_fix(finding(rule_id=""), REGISTRY, now=NOW)

    def test_future_dated_scan_is_rejected(self):
        with self.assertRaises(ValueError):
            confirm_before_fix(finding(observed_at=NOW + timedelta(minutes=5)), REGISTRY, now=NOW)

    def test_stale_scan_is_rejected(self):
        with self.assertRaises(ValueError):
            confirm_before_fix(finding(observed_at=NOW - timedelta(hours=1)), REGISTRY, now=NOW,
                               max_age_seconds=900.0)


class ConfirmBeforeFixTests(unittest.TestCase):
    def test_a_present_finding_confirms_the_assertion(self):
        evidence = confirm_before_fix(finding(present=True), REGISTRY, now=NOW)
        self.assertTrue(evidence.observed_pass)
        self.assertEqual(evidence.assertion, FINDING_CONFIRMED_BEFORE_FIX + ":python.sqli.raw-query:abc123fingerprint")
        self.assertEqual(evidence.source, "sast:semgrep-ci")
        self.assertTrue(evidence.independent)

    def test_an_absent_finding_does_not_confirm_the_assertion(self):
        evidence = confirm_before_fix(finding(present=False), REGISTRY, now=NOW)
        self.assertFalse(evidence.observed_pass)


class ConfirmResolutionTests(unittest.TestCase):
    def test_an_absent_finding_resolves_the_assertion(self):
        evidence = confirm_resolution(finding(present=False), REGISTRY, now=NOW)
        self.assertTrue(evidence.observed_pass)
        self.assertEqual(evidence.assertion, FINDING_RESOLVED + ":python.sqli.raw-query:abc123fingerprint")

    def test_a_still_present_finding_does_not_resolve_the_assertion(self):
        evidence = confirm_resolution(finding(present=True), REGISTRY, now=NOW)
        self.assertFalse(evidence.observed_pass)

    def test_same_fingerprint_tracks_across_before_and_after(self):
        before = confirm_before_fix(finding(present=True), REGISTRY, now=NOW)
        after = confirm_resolution(finding(present=False, observed_at=NOW - timedelta(seconds=10)), REGISTRY, now=NOW)
        self.assertNotEqual(before.assertion, after.assertion)
        self.assertIn("python.sqli.raw-query:abc123fingerprint", before.assertion)
        self.assertIn("python.sqli.raw-query:abc123fingerprint", after.assertion)


class ConfirmNoNewHighSeverityTests(unittest.TestCase):
    def test_empty_diff_passes(self):
        evidence = confirm_no_new_high_severity("billing-api", "semgrep-ci", REGISTRY, [], now=NOW)
        self.assertTrue(evidence.observed_pass)
        self.assertEqual(evidence.assertion, NO_NEW_HIGH_SEVERITY_FINDING)

    def test_a_new_high_severity_finding_fails(self):
        new_finding = finding(finding_id="f-0002", rule_id="python.xss.unescaped", fingerprint="def456")
        evidence = confirm_no_new_high_severity("billing-api", "semgrep-ci", REGISTRY, [new_finding], now=NOW)
        self.assertFalse(evidence.observed_pass)

    def test_a_low_severity_new_finding_is_rejected_as_caller_error(self):
        low = finding(finding_id="f-0003", severity="low")
        with self.assertRaises(ValueError):
            confirm_no_new_high_severity("billing-api", "semgrep-ci", REGISTRY, [low], now=NOW)

    def test_a_finding_from_a_different_scanner_is_rejected(self):
        other = finding(finding_id="f-0004", scanner_id="semgrep-ci")
        # Pretend the caller mixed up which scanner this came from.
        with self.assertRaises(ValueError):
            confirm_no_new_high_severity("billing-api", "unpinned-tool", REGISTRY, [other], now=NOW)

    def test_untrusted_scanner_is_rejected(self):
        with self.assertRaises(ValueError):
            confirm_no_new_high_severity("billing-api", "unreviewed-scanner", REGISTRY, [], now=NOW)


class EvaluateFixTests(unittest.TestCase):
    def _scope(self, before, after):
        return {
            FINDING_CONFIRMED_BEFORE_FIX: (before.asset, before.assertion),
            FINDING_RESOLVED: (after.asset, after.assertion),
            NO_REGRESSION: ("billing-api", "no_regression:billing-api"),
            NO_NEW_HIGH_SEVERITY_FINDING: ("billing-api", NO_NEW_HIGH_SEVERITY_FINDING),
        }

    def test_all_four_verified_is_accepted(self):
        before = confirm_before_fix(finding(present=True), REGISTRY, now=NOW)
        after = confirm_resolution(finding(present=False, observed_at=NOW - timedelta(seconds=5)), REGISTRY, now=NOW)
        no_regression = Evidence(asset="billing-api", assertion="no_regression:billing-api",
                                 observed_pass=True, observed_at=NOW, source="regression-check", independent=True)
        no_new_finding = confirm_no_new_high_severity("billing-api", "semgrep-ci", REGISTRY, [], now=NOW)
        verdict = evaluate_fix(self._scope(before, after), [before, after, no_regression, no_new_finding], now=NOW)
        self.assertTrue(verdict.accepted)
        self.assertEqual(verdict.blocking_reasons, ())

    def test_finding_never_confirmed_before_fix_blocks_acceptance(self):
        # The scanner never actually found this at the claimed fingerprint:
        # a fix cannot be credited with resolving a report that was never real.
        before = confirm_before_fix(finding(present=False), REGISTRY, now=NOW)
        after = confirm_resolution(finding(present=False, observed_at=NOW - timedelta(seconds=5)), REGISTRY, now=NOW)
        no_regression = Evidence(asset="billing-api", assertion="no_regression:billing-api",
                                 observed_pass=True, observed_at=NOW, source="regression-check", independent=True)
        no_new_finding = confirm_no_new_high_severity("billing-api", "semgrep-ci", REGISTRY, [], now=NOW)
        verdict = evaluate_fix(self._scope(before, after), [before, after, no_regression, no_new_finding], now=NOW)
        self.assertFalse(verdict.accepted)
        self.assertIn(FINDING_CONFIRMED_BEFORE_FIX, verdict.blocking_reasons[0])

    def test_finding_still_present_after_fix_blocks_acceptance(self):
        before = confirm_before_fix(finding(present=True), REGISTRY, now=NOW)
        after = confirm_resolution(finding(present=True, observed_at=NOW - timedelta(seconds=5)), REGISTRY, now=NOW)
        no_regression = Evidence(asset="billing-api", assertion="no_regression:billing-api",
                                 observed_pass=True, observed_at=NOW, source="regression-check", independent=True)
        no_new_finding = confirm_no_new_high_severity("billing-api", "semgrep-ci", REGISTRY, [], now=NOW)
        verdict = evaluate_fix(self._scope(before, after), [before, after, no_regression, no_new_finding], now=NOW)
        self.assertFalse(verdict.accepted)
        self.assertIn(FINDING_RESOLVED, "".join(verdict.blocking_reasons))

    def test_a_regression_blocks_acceptance_even_when_the_finding_resolved(self):
        before = confirm_before_fix(finding(present=True), REGISTRY, now=NOW)
        after = confirm_resolution(finding(present=False, observed_at=NOW - timedelta(seconds=5)), REGISTRY, now=NOW)
        no_regression = Evidence(asset="billing-api", assertion="no_regression:billing-api",
                                 observed_pass=False, observed_at=NOW, source="regression-check", independent=True)
        no_new_finding = confirm_no_new_high_severity("billing-api", "semgrep-ci", REGISTRY, [], now=NOW)
        verdict = evaluate_fix(self._scope(before, after), [before, after, no_regression, no_new_finding], now=NOW)
        self.assertFalse(verdict.accepted)
        self.assertIn(NO_REGRESSION, "".join(verdict.blocking_reasons))

    def test_a_new_high_severity_finding_blocks_acceptance(self):
        before = confirm_before_fix(finding(present=True), REGISTRY, now=NOW)
        after = confirm_resolution(finding(present=False, observed_at=NOW - timedelta(seconds=5)), REGISTRY, now=NOW)
        no_regression = Evidence(asset="billing-api", assertion="no_regression:billing-api",
                                 observed_pass=True, observed_at=NOW, source="regression-check", independent=True)
        new_finding = finding(finding_id="f-new", rule_id="python.xss.unescaped", fingerprint="newfp")
        no_new_finding = confirm_no_new_high_severity("billing-api", "semgrep-ci", REGISTRY, [new_finding], now=NOW)
        verdict = evaluate_fix(self._scope(before, after), [before, after, no_regression, no_new_finding], now=NOW)
        self.assertFalse(verdict.accepted)
        self.assertIn(NO_NEW_HIGH_SEVERITY_FINDING, "".join(verdict.blocking_reasons))

    def test_missing_scope_entry_is_a_caller_error(self):
        before = confirm_before_fix(finding(present=True), REGISTRY, now=NOW)
        after = confirm_resolution(finding(present=False, observed_at=NOW - timedelta(seconds=5)), REGISTRY, now=NOW)
        incomplete_scope = {FINDING_CONFIRMED_BEFORE_FIX: (before.asset, before.assertion)}
        with self.assertRaises(ValueError):
            evaluate_fix(incomplete_scope, [before, after], now=NOW)


if __name__=="__main__": unittest.main()
