"""Tests for scheduler-to-independent-assessment feedback."""
import unittest
from datetime import datetime, timezone, timedelta

from predict_shield.assessment import Evidence, Outcome
from predict_shield.verification_cycle import (
    TrackedControl, record_probe, select_probes,
)


class VerificationFeedbackTests(unittest.TestCase):
    NOW = 1800000000

    def control(self):
        return TrackedControl("control-1", "enforcer-b", "revoked-denied",
                              self.NOW - 100, 0.9,
                              changed_at=self.NOW - 40)

    def evidence(self, success=True, independent=True, source="separate-prober"):
        return Evidence("enforcer-b", "revoked-denied", success,
                        datetime.fromtimestamp(self.NOW, tz=timezone.utc),
                        source, independent)

    def test_independent_success_advances_clock_and_clears_change(self):
        control = self.control()
        requests = select_probes([control], now=self.NOW, budget=1,
                                 policy="adaptive")
        self.assertEqual(len(requests), 1)
        updated, record = record_probe(control, requests[0],
                                       [self.evidence()], observed_at=self.NOW)
        self.assertEqual(record.outcome, Outcome.VERIFIED)
        self.assertEqual(updated.last_verified_at, self.NOW)
        self.assertIsNone(updated.changed_at)
        self.assertEqual(select_probes([updated], now=self.NOW,
                                      budget=1, policy="change"), [])

    def test_self_report_cannot_mark_verified(self):
        control = self.control()
        request = select_probes([control], now=self.NOW,
                                budget=1, policy="change")[0]
        updated, record = record_probe(control, request,
                                       [self.evidence(independent=False)],
                                       observed_at=self.NOW)
        self.assertEqual(record.outcome, Outcome.INDETERMINATE)
        self.assertEqual(updated, control)

    def test_independent_failure_preserves_pending_change(self):
        control = self.control()
        request = select_probes([control], now=self.NOW,
                                budget=1, policy="change")[0]
        updated, record = record_probe(control, request, [self.evidence(False)],
                                       observed_at=self.NOW)
        self.assertEqual(record.outcome, Outcome.NOT_VERIFIED)
        self.assertEqual(updated, control)
        self.assertEqual(len(select_probes([updated], now=self.NOW,
                                          budget=1, policy="change")), 1)

    def test_contradiction_is_not_success(self):
        control = self.control()
        request = select_probes([control], now=self.NOW,
                                budget=1, policy="change")[0]
        updated, record = record_probe(control, request,
                                       [self.evidence(True, False, "self"),
                                        self.evidence(False, True, "probe")],
                                       observed_at=self.NOW)
        self.assertEqual(record.outcome, Outcome.NOT_VERIFIED)
        self.assertTrue(record.conflicting_evidence)
        self.assertEqual(updated, control)

    def test_wrong_subject_rejected(self):
        from predict_shield.reverification import ProbeRequest
        with self.assertRaisesRegex(ValueError, "does not match"):
            record_probe(self.control(), ProbeRequest("other", "test", 1),
                         [self.evidence()], observed_at=self.NOW)

    def test_outdated_evidence_does_not_advance_clock(self):
        control = self.control()
        request = select_probes([control], now=self.NOW,
                                budget=1, policy="change")[0]
        stale = Evidence("enforcer-b", "revoked-denied", True,
                         datetime.fromtimestamp(self.NOW-4000, tz=timezone.utc),
                         "independent-prober", True)
        updated, record = record_probe(control, request, [stale],
                                       observed_at=self.NOW)
        self.assertEqual(record.outcome, Outcome.INDETERMINATE)
        self.assertEqual(updated.last_verified_at, control.last_verified_at)

    def test_budget_restricts_probe_requests(self):
        a = self.control()
        b = TrackedControl("control-2", "enforcer-a", "revoked-denied",
                           self.NOW - 100, 0.8, changed_at=self.NOW - 20)
        requests = select_probes([a, b], now=self.NOW, budget=1, policy="change")
        self.assertEqual(len(requests), 1)


if __name__ == "__main__":
    unittest.main()
